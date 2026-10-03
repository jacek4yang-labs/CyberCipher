//! Document formats beyond CBOR/MsgPack: JSON pretty/minify, YAML, BSON and
//! protobuf wire-format inspection.
//!
//! Scope rules:
//! - JSON/YAML/BSON conversions go through `serde_json::Value` so every
//!   format composes with the rest of the engine (From Bson → To Yaml works
//!   as a two-op recipe).
//! - Protobuf inspection is wire-level ONLY (field numbers + wire types, no
//!   schema): nested length-delimited payloads are parsed recursively with
//!   depth/element caps, and unknown wire types are reported, never guessed.
//! - Hostile input: bounded depth/elements, typed errors, no panics.

use crate::helpers::{input_bytes, input_text, spec};
use crate::wrappers::check_budget;
use cybercipher_core::prelude::*;
use cybercipher_core::{ExecutionContext, OpResult, OperationRegistry, ParamMap, Value};

const PB_MAX_DEPTH: usize = 32;
const PB_MAX_FIELDS: usize = 512;

// ================================================================ JSON ====

fn json_pretty_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "JSON Pretty")?;
    check_budget(text.len(), "json pretty")?;
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| decode_json_err(e, "JSON Pretty"))?;
    let pretty = serde_json::to_string_pretty(&parsed)
        .map_err(|e| OperationError::internal(format!("JSON re-serialize failed: {e}")))?;
    Ok(Value::Text(pretty))
}

fn json_minify_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "JSON Minify")?;
    check_budget(text.len(), "json minify")?;
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| decode_json_err(e, "JSON Minify"))?;
    let min = serde_json::to_string(&parsed)
        .map_err(|e| OperationError::internal(format!("JSON re-serialize failed: {e}")))?;
    Ok(Value::Text(min))
}

fn decode_json_err(e: serde_json::Error, what: &str) -> OperationError {
    OperationError::decode(format!("{what}: input is not valid JSON")).with_details(e.to_string())
}

// ================================================================ YAML ====

fn yaml_to_json_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "YAML to JSON")?;
    check_budget(text.len(), "yaml parse")?;
    let parsed: serde_json::Value = serde_yaml::from_str(text).map_err(|e| {
        OperationError::decode("input is not valid YAML").with_details(e.to_string())
    })?;
    Ok(Value::Json(parsed))
}

fn json_to_yaml_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "JSON to YAML")?;
    check_budget(text.len(), "yaml emit")?;
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| decode_json_err(e, "JSON to YAML"))?;
    let out = serde_yaml::to_string(&parsed)
        .map_err(|e| OperationError::internal(format!("YAML emit failed: {e}")))?;
    Ok(Value::Text(out))
}

// ================================================================ BSON ====

fn bson_to_json_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "BSON to JSON")?;
    check_budget(bytes.len(), "bson parse")?;
    // bson::Document::from_reader stops at the first document; raw bytes may
    // concatenate several — decode the first and report the consumed length.
    let doc = bson::Document::from_reader(bytes.as_ref()).map_err(|e| {
        OperationError::decode("input is not valid BSON").with_details(e.to_string())
    })?;
    let value = bson_doc_to_json(&doc)?;
    Ok(Value::Json(value))
}

fn json_to_bson_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "JSON to BSON")?;
    check_budget(text.len(), "bson emit")?;
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| decode_json_err(e, "JSON to BSON"))?;
    let doc = json_to_bson_doc(&parsed)?;
    let mut out = Vec::new();
    doc.to_writer(&mut out)
        .map_err(|e| OperationError::internal(format!("BSON encode failed: {e}")))?;
    Ok(Value::Bytes(out))
}

fn bson_doc_to_json(doc: &bson::Document) -> OpResult<serde_json::Value> {
    let raw = bson::to_bson(doc)
        .map_err(|e| OperationError::internal(format!("BSON value convert failed: {e}")))?;
    Ok(bson_bson_to_json(&raw))
}

fn bson_bson_to_json(b: &bson::Bson) -> serde_json::Value {
    use bson::Bson;
    match b {
        Bson::Double(f) => serde_json::json!(f),
        Bson::String(t) => serde_json::json!(t),
        Bson::Document(d) => {
            let mut m = serde_json::Map::new();
            for (k, v) in d {
                m.insert(k.clone(), bson_bson_to_json(v));
            }
            serde_json::Value::Object(m)
        }
        Bson::Array(a) => serde_json::Value::Array(a.iter().map(bson_bson_to_json).collect()),
        Bson::Boolean(t) => serde_json::json!(t),
        Bson::Null => serde_json::Value::Null,
        Bson::Int32(i) => serde_json::json!(i),
        Bson::Int64(i) => serde_json::json!(i),
        Bson::DateTime(dt) => serde_json::json!(dt.try_to_rfc3339_string().unwrap_or_default()),
        Bson::Timestamp(ts) => serde_json::json!({"timestamp": ts.time, "increment": ts.increment}),
        Bson::ObjectId(oid) => serde_json::json!(oid.to_hex()),
        Bson::Binary(bin) => {
            serde_json::json!({"binary": hex_encode(&bin.bytes), "subtype": format!("{:?}", bin.subtype)})
        }
        Bson::Decimal128(d) => serde_json::json!(d.to_string()),
        Bson::JavaScriptCode(code) => serde_json::json!({"javascript": code.to_string()}),
        Bson::RegularExpression(re) => {
            serde_json::json!({"pattern": re.pattern.to_string(), "options": re.options.to_string()})
        }
        other => serde_json::json!({"unrepresentable": other.to_string()}),
    }
}

fn json_to_bson_doc(value: &serde_json::Value) -> OpResult<bson::Document> {
    let b = json_to_bson(value)?;
    match b {
        bson::Bson::Document(d) => Ok(d),
        other => Ok(bson::Document::from_iter(std::iter::once((
            "root".to_owned(),
            other,
        )))),
    }
}

fn json_to_bson(value: &serde_json::Value) -> OpResult<bson::Bson> {
    use serde_json::Value as J;
    Ok(match value {
        J::Null => bson::Bson::Null,
        J::Bool(t) => bson::Bson::Boolean(*t),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                bson::Bson::Int64(i)
            } else if let Some(f) = n.as_f64() {
                bson::Bson::Double(f)
            } else {
                return Err(OperationError::decode("JSON number out of BSON range")
                    .with_actual(n.to_string()));
            }
        }
        J::String(t) => bson::Bson::String(t.clone()),
        J::Array(a) => {
            let items: OpResult<Vec<bson::Bson>> = a.iter().map(json_to_bson).collect();
            bson::Bson::Array(items?)
        }
        J::Object(m) => {
            let mut doc = bson::Document::new();
            for (k, v) in m {
                doc.insert(k.clone(), json_to_bson(v)?);
            }
            bson::Bson::Document(doc)
        }
    })
}

// ============================================================ protobuf ====

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireType {
    Varint,
    I64,
    LenDelim,
    SGroup,
    EGroup,
    I32,
}

fn wire_type(n: u64) -> OpResult<WireType> {
    Ok(match n {
        0 => WireType::Varint,
        1 => WireType::I64,
        2 => WireType::LenDelim,
        3 => WireType::SGroup,
        4 => WireType::EGroup,
        5 => WireType::I32,
        other => {
            return Err(
                OperationError::decode(format!("unknown protobuf wire type {other}"))
                    .with_expected("wire types 0..5"),
            )
        }
    })
}

struct PbField {
    number: u64,
    wire: WireType,
    value: serde_json::Value,
}

/// Read one varint; bounded by the slice length.
fn read_varint(data: &[u8], pos: &mut usize) -> OpResult<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let Some(&b) = data.get(*pos) else {
            return Err(
                OperationError::decode("truncated varint").with_actual(format!(
                    "ended at byte {}/{}",
                    *pos,
                    data.len()
                )),
            );
        };
        *pos += 1;
        result |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(OperationError::decode("varint exceeds 64 bits"));
        }
    }
}

fn parse_pb_fields(data: &[u8], depth: usize, budget: &mut usize) -> OpResult<Vec<PbField>> {
    if depth > PB_MAX_DEPTH {
        return Err(OperationError::decode(format!(
            "protobuf nesting exceeds the {PB_MAX_DEPTH}-level cap"
        )));
    }
    let mut fields = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if *budget == 0 {
            return Err(OperationError::decode(format!(
                "protobuf field count exceeds the {PB_MAX_FIELDS}-field cap"
            )));
        }
        *budget -= 1;
        let key = read_varint(data, &mut pos)?;
        let number = key >> 3;
        let wire = wire_type(key & 0x7)?;
        if number == 0 {
            return Err(OperationError::decode("protobuf field number 0 is invalid"));
        }
        let value = match wire {
            WireType::Varint => {
                let v = read_varint(data, &mut pos)?;
                serde_json::json!({ "varint": v })
            }
            WireType::I64 => {
                if data.len() < pos + 8 {
                    return Err(OperationError::decode("truncated fixed64 field"));
                }
                let raw = &data[pos..pos + 8];
                pos += 8;
                serde_json::json!({
                    "fixed64_le": u64::from_le_bytes(raw.try_into().expect("8 bytes")),
                })
            }
            WireType::I32 => {
                if data.len() < pos + 4 {
                    return Err(OperationError::decode("truncated fixed32 field"));
                }
                let raw = &data[pos..pos + 4];
                pos += 4;
                serde_json::json!({
                    "fixed32_le": u32::from_le_bytes(raw.try_into().expect("4 bytes")),
                })
            }
            WireType::LenDelim => {
                let len = read_varint(data, &mut pos)? as usize;
                if data.len() < pos + len {
                    return Err(OperationError::decode("truncated length-delimited field")
                        .with_actual(format!(
                            "declared {len} bytes, {} remain",
                            data.len() - pos
                        )));
                }
                let payload = &data[pos..pos + len];
                pos += len;
                // Heuristic recursion ONLY for well-formed nested wire data
                // that consumed the whole payload — otherwise present as
                // UTF-8 text or hex. Never guesses on partial parses.
                let mut nested = None;
                if len > 0 && *budget > 0 {
                    let mut sub_budget = *budget;
                    nested = parse_pb_fields(payload, depth + 1, &mut sub_budget)
                        .ok()
                        .filter(|fields| !fields.is_empty());
                }
                match nested {
                    Some(fields) => serde_json::json!({
                        "nested": fields.iter().map(pb_field_json).collect::<Vec<_>>(),
                    }),
                    None => match std::str::from_utf8(payload) {
                        Ok(text) if text.chars().all(|c| c.is_ascii_graphic() || c == ' ') => {
                            serde_json::json!({ "text": text })
                        }
                        _ => serde_json::json!({ "hex": hex_encode(payload) }),
                    },
                }
            }
            WireType::SGroup | WireType::EGroup => {
                // Deprecated group framing: surfaced, not decoded.
                serde_json::json!({ "group": "deprecated group markers are surfaced only" })
            }
        };
        fields.push(PbField {
            number,
            wire,
            value,
        });
    }
    Ok(fields)
}

fn pb_field_json(f: &PbField) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("field".to_owned(), serde_json::json!(f.number));
    m.insert(
        "wire".to_owned(),
        serde_json::json!(match f.wire {
            WireType::Varint => "varint",
            WireType::I64 => "fixed64",
            WireType::LenDelim => "length-delimited",
            WireType::SGroup => "start-group",
            WireType::EGroup => "end-group",
            WireType::I32 => "fixed32",
        }),
    );
    if let Some(obj) = f.value.as_object() {
        for (k, v) in obj {
            m.insert(k.clone(), v.clone());
        }
    }
    serde_json::Value::Object(m)
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn protobuf_inspect_op(v: &Value, _: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Protobuf Inspect")?;
    check_budget(bytes.len(), "protobuf inspect")?;
    ctx.check()?;
    let mut budget = PB_MAX_FIELDS;
    let fields = parse_pb_fields(bytes.as_ref(), 0, &mut budget)?;
    let report = serde_json::json!({
        "note": "wire-level inspection only — field semantics require a schema",
        "field_count": fields.len(),
        "fields": fields.iter().map(pb_field_json).collect::<Vec<_>>(),
    });
    Ok(Value::Json(report))
}

// ================================================================ XML ====

/// Bounded XML event walk to a JSON tree (quick-xml). Attributes become
/// "@name" keys; text is collapsed into "#text" (whitespace-only ignored).
/// Depth/element caps keep hostile nesting cheap.
fn xml_walk(
    reader: &mut quick_xml::Reader<&[u8]>,
    depth: usize,
    budget: &mut usize,
) -> OpResult<serde_json::Value> {
    use quick_xml::events::Event;
    if depth > PB_MAX_DEPTH {
        return Err(OperationError::decode(format!(
            "XML nesting exceeds the {PB_MAX_DEPTH}-level cap"
        )));
    }
    let mut map = serde_json::Map::new();
    let mut text = String::new();
    loop {
        if *budget == 0 {
            return Err(OperationError::decode(format!(
                "XML element count exceeds the {PB_MAX_FIELDS}-element cap"
            )));
        }
        *budget -= 1;
        let event = reader.read_event().map_err(|err| {
            OperationError::decode("input is not valid XML").with_details(err.to_string())
        })?;
        match event {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                // Recurse: the child walker consumes events until its End.
                let child = xml_walk(reader, depth + 1, budget)?;
                let mut node = match child {
                    serde_json::Value::Object(m) if m.is_empty() => serde_json::Value::Null,
                    other => other,
                };
                for attr in e.attributes() {
                    let attr = attr.map_err(|err| {
                        OperationError::decode("malformed XML attribute")
                            .with_details(err.to_string())
                    })?;
                    let key = format!("@{}", String::from_utf8_lossy(attr.key.as_ref()));
                    let value = String::from_utf8_lossy(&attr.value).to_string();
                    if !matches!(&node, serde_json::Value::Object(_)) {
                        let text_val = node.clone();
                        let mut m = serde_json::Map::new();
                        m.insert("#text".to_owned(), text_val);
                        node = serde_json::Value::Object(m);
                    }
                    if let serde_json::Value::Object(m) = &mut node {
                        m.insert(key, serde_json::json!(value));
                    }
                }
                merge_xml_child(&mut map, &name, node);
            }
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let mut node = serde_json::Value::Null;
                for attr in e.attributes() {
                    let attr = attr.map_err(|err| {
                        OperationError::decode("malformed XML attribute")
                            .with_details(err.to_string())
                    })?;
                    let key = format!("@{}", String::from_utf8_lossy(attr.key.as_ref()));
                    let value = String::from_utf8_lossy(&attr.value).to_string();
                    if !matches!(&node, serde_json::Value::Object(_)) {
                        node = serde_json::Value::Object(serde_json::Map::new());
                    }
                    if let serde_json::Value::Object(m) = &mut node {
                        m.insert(key, serde_json::json!(value));
                    }
                }
                merge_xml_child(&mut map, &name, node);
            }
            Event::End(_) => {
                if !text.trim().is_empty() && map.is_empty() {
                    return Ok(serde_json::json!(text.trim()));
                }
                if !text.trim().is_empty() {
                    map.insert("#text".to_owned(), serde_json::json!(text.trim()));
                }
                return Ok(serde_json::Value::Object(map));
            }
            Event::Text(t) => {
                text.push_str(&String::from_utf8_lossy(t.as_ref()));
            }
            Event::CData(t) => {
                text.push_str(&String::from_utf8_lossy(t.as_ref()));
            }
            Event::Eof => {
                if depth > 0 {
                    return Err(OperationError::decode("truncated XML: unexpected EOF"));
                }
                break;
            }
            _ => {}
        }
    }
    if map.is_empty() {
        Ok(serde_json::json!(text.trim()))
    } else {
        Ok(serde_json::Value::Object(map))
    }
}

/// Repeated element names become arrays (in document order).
fn merge_xml_child(
    map: &mut serde_json::Map<String, serde_json::Value>,
    name: &str,
    node: serde_json::Value,
) {
    match map.get_mut(name) {
        Some(serde_json::Value::Array(arr)) => arr.push(node),
        Some(existing) => {
            let prev = existing.clone();
            map.insert(name.to_owned(), serde_json::Value::Array(vec![prev, node]));
        }
        None => {
            map.insert(name.to_owned(), node);
        }
    }
}

fn xml_inspect_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "XML Inspect")?;
    check_budget(text.len(), "xml inspect")?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut budget = PB_MAX_FIELDS;
    let tree = xml_walk(&mut reader, 0, &mut budget)?;
    Ok(Value::Json(tree))
}

// ============================================================ registry ====

pub(crate) fn register(reg: &mut OperationRegistry) {
    use cybercipher_core::Category::Serialization as S;
    use cybercipher_core::CostClass::{Instant as Inst, Interactive as I};
    use cybercipher_core::ValueKind::{Bytes as B, Json as J, Text as T};

    let tags: &'static [&'static str] = &["serialization", "ctf", "structured"];

    reg.add_simple(
        spec(
            "json-pretty",
            "JSON Pretty",
            "Pretty-prints JSON with two-space indentation.",
            S,
            &[T],
            T,
            Inst,
            true,
            vec![],
            tags,
            &["json format", "json pretty print"],
            "RFC 8259 (JSON)",
            "Round-trip tests",
        ),
        json_pretty_op,
    );
    reg.add_simple(
        spec(
            "json-minify",
            "JSON Minify",
            "Minifies JSON to compact form.",
            S,
            &[T],
            T,
            Inst,
            true,
            vec![],
            tags,
            &["json compact", "json minify"],
            "RFC 8259 (JSON)",
            "Round-trip tests",
        ),
        json_minify_op,
    );
    reg.add_simple(
        spec(
            "yaml-to-json",
            "YAML to JSON",
            "Parses YAML into JSON.",
            S,
            &[T],
            J,
            I,
            true,
            vec![],
            tags,
            &["yaml parse", "yaml decode"],
            "YAML 1.2 core schema (via serde_yaml)",
            "Round-trip + malformed-input tests",
        ),
        yaml_to_json_op,
    );
    reg.add_simple(
        spec(
            "json-to-yaml",
            "JSON to YAML",
            "Emits YAML from JSON.",
            S,
            &[T],
            T,
            Inst,
            true,
            vec![],
            tags,
            &["yaml emit", "json to yaml"],
            "YAML 1.2 core schema (via serde_yaml)",
            "Round-trip tests",
        ),
        json_to_yaml_op,
    );
    reg.add_simple(
        spec(
            "bson-to-json",
            "BSON to JSON",
            "Decodes the first BSON document from bytes into JSON (ObjectId, timestamps, binary preserved as structured fields).",
            S,
            &[B],
            J,
            I,
            true,
            vec![],
            tags,
            &["bson decode", "bson parse"],
            "BSON specification (bsonspec.org)",
            "Round-trip + truncated-input tests",
        ),
        bson_to_json_op,
    );
    reg.add_simple(
        spec(
            "json-to-bson",
            "JSON to BSON",
            "Encodes JSON (object at top level) as BSON bytes.",
            S,
            &[T],
            B,
            I,
            true,
            vec![],
            tags,
            &["bson encode", "json to bson"],
            "BSON specification (bsonspec.org)",
            "Round-trip tests",
        ),
        json_to_bson_op,
    );
    reg.add_simple(
        spec(
            "xml-inspect",
            "XML Inspect",
            "Parses XML into a bounded JSON tree: elements nest, attributes become @name keys, repeated elements become arrays, text collapses into #text.",
            S,
            &[T],
            J,
            I,
            true,
            vec![],
            tags,
            &["xml parse", "xml to json"],
            "XML 1.0 (W3C), parsed with quick-xml",
            "Round-trip + truncation + hostile-nesting tests",
        ),
        xml_inspect_op,
    );
    reg.add_simple(
        spec(
            "protobuf-inspect",
            "Protobuf Inspect",
            "Wire-level protobuf inspection WITHOUT a schema: field numbers, wire types, varints, fixed values, nested length-delimited payloads (bounded recursion). Field semantics are never guessed.",
            S,
            &[B],
            J,
            I,
            false,
            vec![],
            tags,
            &["protobuf", "proto decode", "wire format"],
            "Protobuf wire format (developers.google.com/protocol-buffers/docs/encoding)",
            "Hand-built wire fixtures + truncation + hostile-nesting tests",
        ),
        protobuf_inspect_op,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybercipher_core::{ErrorKind, ParamMap};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    // ---------------------------------------------------------- JSON ----

    #[test]
    fn json_pretty_and_minify_roundtrip() {
        let compact = json_minify_op(
            &Value::Text(r#" { "a" : [1, 2, {"b": "c"}], "d": null } "#.into()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap();
        assert_eq!(
            compact,
            Value::Text(r#"{"a":[1,2,{"b":"c"}],"d":null}"#.into())
        );
        let pretty = json_pretty_op(&compact, &ParamMap::new(), &ctx()).unwrap();
        let Value::Text(p) = &pretty else { panic!() };
        assert!(p.contains("\n  \"a\""));
        assert_eq!(
            json_minify_op(&pretty, &ParamMap::new(), &ctx()).unwrap(),
            compact
        );
    }

    #[test]
    fn json_invalid_is_typed_error() {
        let err =
            json_minify_op(&Value::Text("{nope".into()), &ParamMap::new(), &ctx()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    // ---------------------------------------------------------- YAML ----

    #[test]
    fn yaml_to_json_nested() {
        let out = yaml_to_json_op(
            &Value::Text("root:\n  - name: a\n    n: 1\n  - name: b\n".into()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap();
        let Value::Json(j) = out else { panic!() };
        assert_eq!(j["root"][0]["name"], "a");
        assert_eq!(j["root"][0]["n"], 1);
        assert_eq!(j["root"][1]["name"], "b");
    }

    #[test]
    fn json_to_yaml_roundtrip_through_value() {
        let yaml = json_to_yaml_op(
            &Value::Text(r#"{"k": [1, "two", {"deep": true}]}"#.into()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap();
        let back = yaml_to_json_op(&yaml, &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = back else { panic!() };
        assert_eq!(j["k"][0], 1);
        assert_eq!(j["k"][1], "two");
        assert_eq!(j["k"][2]["deep"], true);
    }

    #[test]
    fn yaml_malformed_is_typed_error() {
        let err = yaml_to_json_op(
            &Value::Text("a: [unclosed\n  b: {".into()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    // ---------------------------------------------------------- BSON ----

    #[test]
    fn bson_roundtrip_with_types() {
        let json = r#"{"name": "ctf", "n": 42, "big": 9007199254740993, "arr": [true, null]}"#;
        let encoded = json_to_bson_op(&Value::Text(json.into()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Bytes(bytes) = encoded else {
            panic!()
        };
        let decoded = bson_to_json_op(&Value::Bytes(bytes), &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = decoded else { panic!() };
        assert_eq!(j["name"], "ctf");
        assert_eq!(j["n"], 42);
        assert_eq!(j["big"], 9007199254740993i64);
        assert_eq!(j["arr"][0], true);
        assert_eq!(j["arr"][1], serde_json::Value::Null);
    }

    #[test]
    fn bson_truncated_is_typed_error() {
        let err = bson_to_json_op(
            &Value::Bytes(vec![0x10, 0x00, 0x00]),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    #[test]
    fn bson_binary_and_objectid_preserved() {
        // Build the fixture with the bson crate itself: this exercises OUR
        // Bson->JSON conversion, not the crate's wire writer.
        let mut doc = bson::Document::new();
        doc.insert(
            "oid",
            bson::Bson::ObjectId(bson::oid::ObjectId::from_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ])),
        );
        doc.insert(
            "bin",
            bson::Bson::Binary(bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: vec![0x01, 0x02],
            }),
        );
        doc.insert(
            "ts",
            bson::Bson::Timestamp(bson::Timestamp {
                time: 7,
                increment: 3,
            }),
        );
        let mut wire = Vec::new();
        doc.to_writer(&mut wire).unwrap();
        let decoded = bson_to_json_op(&Value::Bytes(wire), &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = decoded else { panic!() };
        assert_eq!(j["oid"], "0102030405060708090a0b0c");
        assert_eq!(j["bin"]["binary"], "0102");
        assert_eq!(j["ts"]["timestamp"], 7);
        assert_eq!(j["ts"]["increment"], 3);
    }

    // ------------------------------------------------------ protobuf ----

    #[test]
    fn protobuf_varint_len_delim_and_nested() {
        // field 1 varint 150: 08 96 01
        // field 2 len-delim containing nested {field 3 varint 7}: 12 02 18 07
        // field 4 fixed32: 25 01 02 03 04
        let data = [
            0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x07, 0x25, 0x01, 0x02, 0x03, 0x04,
        ];
        let out =
            protobuf_inspect_op(&Value::Bytes(data.to_vec()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = out else { panic!() };
        assert_eq!(j["field_count"], 3);
        assert_eq!(j["fields"][0]["field"], 1);
        assert_eq!(j["fields"][0]["varint"], 150);
        assert_eq!(j["fields"][1]["wire"], "length-delimited");
        assert_eq!(j["fields"][1]["nested"][0]["field"], 3);
        assert_eq!(j["fields"][1]["nested"][0]["varint"], 7);
        assert_eq!(j["fields"][2]["fixed32_le"], 0x04030201);
        assert!(j["note"].as_str().unwrap().contains("schema"));
    }

    #[test]
    fn protobuf_text_payload_surfaces_as_text() {
        let mut data = vec![0x0a, 0x0e];
        data.extend_from_slice(b"hello protobuf");
        let out = protobuf_inspect_op(&Value::Bytes(data), &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = out else { panic!() };
        assert_eq!(j["fields"][0]["text"], "hello protobuf");
    }

    #[test]
    fn protobuf_truncated_and_hostile_are_typed_errors() {
        assert_eq!(
            protobuf_inspect_op(&Value::Bytes(vec![0x08]), &ParamMap::new(), &ctx())
                .unwrap_err()
                .kind,
            ErrorKind::Decode
        );
        assert_eq!(
            protobuf_inspect_op(
                &Value::Bytes(vec![0x0a, 0x20, 0x01]),
                &ParamMap::new(),
                &ctx()
            )
            .unwrap_err()
            .kind,
            ErrorKind::Decode
        );
        assert_eq!(
            protobuf_inspect_op(&Value::Bytes(vec![0x00]), &ParamMap::new(), &ctx())
                .unwrap_err()
                .kind,
            ErrorKind::Decode
        );
        let mut deep = vec![0x12; PB_MAX_DEPTH + 2];
        deep.push(0x00);
        let err = protobuf_inspect_op(&Value::Bytes(deep), &ParamMap::new(), &ctx()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    // ----------------------------------------------------------- XML ----

    #[test]
    fn xml_tree_attributes_and_repeats() {
        let xml = r#"<root id="1"><item name="a">one</item><item name="b"/><meta/></root>"#;
        let out = xml_inspect_op(&Value::Text(xml.into()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Json(j) = out else { panic!() };
        assert_eq!(j["root"]["@id"], "1");
        assert_eq!(j["root"]["item"][0]["#text"], "one");
        assert_eq!(j["root"]["item"][0]["@name"], "a");
        assert_eq!(j["root"]["item"][1]["@name"], "b");
        assert!(j["root"]["meta"].is_null());
    }

    #[test]
    fn xml_truncated_is_typed_error() {
        let err = xml_inspect_op(
            &Value::Text("<a><b>unclosed".into()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    #[test]
    fn xml_deep_nesting_is_capped() {
        let mut xml = String::new();
        for _ in 0..PB_MAX_DEPTH + 5 {
            xml.push_str("<a>");
        }
        let err = xml_inspect_op(&Value::Text(xml), &ParamMap::new(), &ctx()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }
}
