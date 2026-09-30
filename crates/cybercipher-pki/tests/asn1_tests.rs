//! Integration tests for the generic DER/ASN.1 tree inspector
//! (`cybercipher_pki::asn1`). All fixtures are hand-built DER byte strings —
//! no external test data required.

use cybercipher_core::{ErrorKind, OperationError};
use cybercipher_pki::asn1::{
    oid_name, parse_der_nodes, parse_der_tree, Asn1Class, Asn1Node, Asn1Value, DEFAULT_MAX_DEPTH,
    MAX_INPUT_SIZE,
};

// ---------------------------------------------------------------------------
// Tiny DER builder helpers (test-only)
// ---------------------------------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else if content.len() <= 0xff {
        out.push(0x81);
        out.push(content.len() as u8);
    } else {
        out.push(0x82);
        out.push((content.len() >> 8) as u8);
        out.push((content.len() & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    let joined: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    tlv(0x30, &joined)
}

fn integer(content: &[u8]) -> Vec<u8> {
    tlv(0x02, content)
}

fn oid(dotted: &str) -> Vec<u8> {
    // Only the OIDs used in these tests; encode from pre-baked content bytes.
    let content: &[u8] = match dotted {
        "2.5.4.3" => &[0x55, 0x04, 0x03],
        "1.2.840.113549.1.1.11" => &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        other => panic!("test helper does not know OID {other}"),
    };
    tlv(0x06, content)
}

fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

fn printable(text: &str) -> Vec<u8> {
    tlv(0x13, text.as_bytes())
}

fn utctime(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

fn null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// A mini "Name" structure: RDN sequence with one commonName.
fn name_cn(cn: &str) -> Vec<u8> {
    // Name ::= SEQUENCE OF SET OF { type OID, value }
    let rdn = tlv(0x31, &seq(&[&oid("2.5.4.3"), &utf8(cn)]));
    seq(&[&rdn])
}

fn node_value(node: &Asn1Node) -> &Asn1Value {
    node.value
        .as_ref()
        .expect("node should carry a decoded value")
}

// ---------------------------------------------------------------------------
// Fixture: nested SEQUENCE / OID / INTEGER / strings
// ---------------------------------------------------------------------------

fn sample_tbs() -> Vec<u8> {
    seq(&[
        &integer(&[0x01, 0xe2, 0x40]), // 123456
        &name_cn("alice"),
        &boolean(true),
        &null(),
        &oid("1.2.840.113549.1.1.11"),
        &printable("CyberCipher"),
        &utctime("260101000000Z"),
    ])
}

#[test]
fn nested_structure_round_trip() {
    let der = sample_tbs();
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).expect("fixture must parse");
    assert_eq!(tree.len(), 1);
    let root = &tree[0];

    assert_eq!(root.tag_class, Asn1Class::Universal);
    assert_eq!(root.tag_number, 16);
    assert_eq!(root.tag_name.as_deref(), Some("SEQUENCE"));
    assert!(root.constructed);
    assert_eq!(root.offset, 0);
    assert_eq!(root.total_len, der.len(), "root consumes the whole input");
    assert_eq!(root.children.len(), 7);
    assert!(root.value.is_none(), "constructed nodes have no value");
    assert!(root.hex_preview.is_none());

    // INTEGER 123456
    let integer_node = &root.children[0];
    assert_eq!(integer_node.tag_name.as_deref(), Some("INTEGER"));
    match node_value(integer_node) {
        Asn1Value::Integer { value, hex } => {
            assert_eq!(value, "123456");
            assert_eq!(hex, "01e240");
        }
        other => panic!("expected INTEGER, got {other:?}"),
    }

    // Name: SEQUENCE -> SET -> SEQUENCE(OID + UTF8String)
    let name = &root.children[1];
    assert_eq!(name.children.len(), 1, "one RDN SET");
    let rdn_set = &name.children[0];
    assert_eq!(rdn_set.tag_name.as_deref(), Some("SET"));
    let attr = &rdn_set.children[0];
    assert_eq!(attr.children.len(), 2);
    match node_value(&attr.children[0]) {
        Asn1Value::ObjectIdentifier { dotted, name } => {
            assert_eq!(dotted, "2.5.4.3");
            assert_eq!(name.as_deref(), Some("commonName"));
        }
        other => panic!("expected OID, got {other:?}"),
    }
    match node_value(&attr.children[1]) {
        Asn1Value::Utf8String { text } => assert_eq!(text, "alice"),
        other => panic!("expected UTF8String, got {other:?}"),
    }

    // BOOLEAN / NULL
    match node_value(&root.children[2]) {
        Asn1Value::Boolean { value: true } => {}
        other => panic!("expected BOOLEAN true, got {other:?}"),
    }
    match node_value(&root.children[3]) {
        Asn1Value::Null => {}
        other => panic!("expected NULL, got {other:?}"),
    }

    // RSA OID with well-known name
    match node_value(&root.children[4]) {
        Asn1Value::ObjectIdentifier { dotted, name } => {
            assert_eq!(dotted, "1.2.840.113549.1.1.11");
            assert_eq!(name.as_deref(), Some("sha256WithRSAEncryption"));
        }
        other => panic!("expected OID, got {other:?}"),
    }

    // PrintableString / UTCTime
    match node_value(&root.children[5]) {
        Asn1Value::PrintableString { text } => assert_eq!(text, "CyberCipher"),
        other => panic!("expected PrintableString, got {other:?}"),
    }
    match node_value(&root.children[6]) {
        Asn1Value::UtcTime { text } => assert_eq!(text, "260101000000Z"),
        other => panic!("expected UTCTime, got {other:?}"),
    }

    // Absolute offsets line up with the real byte positions.
    for child in &root.children {
        assert!(child.offset >= root.value_offset);
        assert!(child.offset + child.total_len <= der.len());
        assert_eq!(
            child.offset + child.total_len,
            child.value_offset + child.value_len
        );
    }
}

#[test]
fn serde_output_is_snake_case_json() {
    let der = sample_tbs();
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let json = serde_json::to_value(&tree).unwrap();
    let root = json.as_array().unwrap()[0].as_object().unwrap();
    for key in [
        "tag_class",
        "tag_number",
        "tag_name",
        "constructed",
        "offset",
        "header_len",
        "value_offset",
        "value_len",
        "total_len",
        "children",
    ] {
        assert!(root.contains_key(key), "missing key {key} in {root:?}");
    }
    let integer_node = &root["children"][0];
    assert_eq!(integer_node["value"]["type"], "integer");
    assert_eq!(integer_node["value"]["value"], "123456");
    // Name -> RDN SET -> attribute SEQUENCE -> OID
    let oid_node = &root["children"][1]["children"][0]["children"][0]["children"][0];
    assert_eq!(oid_node["value"]["type"], "object_identifier");
    assert_eq!(oid_node["value"]["name"], "commonName");
    // Round-trips through serde without loss.
    let back: Vec<Asn1Node> = serde_json::from_value(json).unwrap();
    assert_eq!(back, tree);
}

// ---------------------------------------------------------------------------
// Bounds: depth cap, size cap, truncation, trailing bytes
// ---------------------------------------------------------------------------

fn nested_seq(depth: usize) -> Vec<u8> {
    let mut node = integer(&[0x00]);
    for _ in 0..depth {
        node = seq(&[&node]);
    }
    node
}

#[test]
fn depth_cap_rejects_deep_nesting() {
    let deep = nested_seq(DEFAULT_MAX_DEPTH); // depth = 32 SEQUENCEs
    let err = parse_der_tree(&deep, DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput);
    assert!(err.message.contains("maximum depth"), "got: {err:?}");
    assert!(err.expected.as_deref().unwrap().contains("<= 32"));

    // A lower cap rejects proportionally shallower trees.
    let shallow = nested_seq(4);
    let err = parse_der_tree(&shallow, 4).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput);

    // Same shallow tree parses fine with the default cap.
    parse_der_tree(&shallow, DEFAULT_MAX_DEPTH).unwrap();

    // max_depth = 0 is a parameter error.
    let err = parse_der_tree(&shallow, 0).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidParam);
    assert_eq!(err.parameter.as_deref(), Some("max_depth"));
}

#[test]
fn trailing_bytes_are_detected() {
    let mut der = sample_tbs();
    der.extend_from_slice(&[0x05, 0x00]); // stray NULL after the root
    let err = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    assert!(err.message.contains("2 trailing bytes"), "got: {err:?}");

    // parse_der_nodes accepts the concatenated objects instead.
    let nodes = parse_der_nodes(&der, DEFAULT_MAX_DEPTH).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[1].tag_name.as_deref(), Some("NULL"));

    // One stray byte is also caught.
    let mut der = sample_tbs();
    der.push(0x00);
    let err = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap_err();
    assert!(err.message.contains("1 trailing bytes"), "got: {err:?}");
}

#[test]
fn truncation_and_malformed_lengths_are_typed_errors() {
    // Declared value longer than the input (root cut short mid-value).
    let der = sample_tbs();
    let err = parse_der_tree(&der[..der.len() - 4], DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    assert!(
        err.message.contains("past the enclosing boundary"),
        "got: {err:?}"
    );

    // Input too short for even the identifier + length headers.
    let err = parse_der_tree(&[0x30], DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    assert!(err.message.contains("truncated"), "got: {err:?}");

    // Declared length longer than the input (long form).
    let lying = vec![0x30, 0x84, 0x00, 0x10, 0x00, 0x00, 0x01];
    let err = parse_der_tree(&lying, DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    assert!(
        err.message.contains("past the enclosing boundary"),
        "got: {err:?}"
    );

    // Indefinite (BER) length rejected.
    let ber = vec![0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00];
    let err = parse_der_tree(&ber, DEFAULT_MAX_DEPTH).unwrap_err();
    assert!(err.message.contains("indefinite"), "got: {err:?}");

    // Long-form length longer than 4 octets rejected.
    let huge = vec![0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01];
    let err = parse_der_tree(&huge, DEFAULT_MAX_DEPTH).unwrap_err();
    assert!(err.message.contains("cap is 4"), "got: {err:?}");

    // Empty input.
    let err = parse_der_tree(&[], DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);

    // Size cap.
    let too_big = vec![0u8; MAX_INPUT_SIZE + 1];
    let err = parse_der_tree(&too_big, DEFAULT_MAX_DEPTH).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput);
    assert!(err.message.contains("size cap"), "got: {err:?}");
}

// ---------------------------------------------------------------------------
// Unknown tags: hex preview, context class, high tag numbers
// ---------------------------------------------------------------------------

#[test]
fn unknown_tag_renders_hex_preview() {
    // Context-tagged primitive [3] with 4 content bytes: 0x83 0x04 <bytes>
    let der = seq(&[&tlv(0x83, &[0xde, 0xad, 0xbe, 0xef])]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let root = &tree[0];
    let child = &root.children[0];
    assert_eq!(child.tag_class, Asn1Class::Context);
    assert_eq!(child.tag_number, 3);
    assert_eq!(child.tag_name, None);
    assert!(!child.constructed);
    assert_eq!(child.value, None);
    assert_eq!(child.hex_preview.as_deref(), Some("deadbeef"));
    assert_eq!(child.value_len, 4);

    // A private-class constructed high tag (private [31]) gets children,
    // not a preview. 0xff 0x1f = private | constructed | high-tag form,
    // second identifier octet 0x1f terminates the tag number.
    let der = seq(&[&[0xff, 0x1f, 0x03, 0x02, 0x01, 0x2a]]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let child = &tree[0].children[0];
    assert_eq!(child.tag_class, Asn1Class::Private);
    assert_eq!(child.tag_number, 31);
    assert!(child.constructed);
    assert_eq!(child.children.len(), 1);
    assert_eq!(child.children[0].tag_name.as_deref(), Some("INTEGER"));

    // Unknown universal primitive (tag 15 is reserved) -> raw preview.
    let der = tlv(0x0f, &[0x01, 0x02, 0x03]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    assert_eq!(tree[0].hex_preview.as_deref(), Some("010203"));
    assert_eq!(tree[0].tag_name, None);
}

#[test]
fn long_form_lengths_and_high_tag_numbers() {
    // 200-byte OCTET STRING: long-form length 0x81 0xc8.
    let content = vec![0x41u8; 200];
    let der = tlv(0x04, &content);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    assert_eq!(tree[0].header_len, 3, "tag + 2 length octets");
    assert_eq!(tree[0].value_len, 200);
    assert_eq!(tree[0].value_offset, 3);
    assert_eq!(tree[0].total_len, 203);
    match node_value(&tree[0]) {
        Asn1Value::OctetString { hex } => assert_eq!(hex.len(), 400),
        other => panic!("expected OCTET STRING, got {other:?}"),
    }

    // > 255-byte content uses 0x82 two-octet length.
    let content = vec![0x42u8; 300];
    let der = tlv(0x04, &content);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    assert_eq!(tree[0].header_len, 4);
    assert_eq!(tree[0].value_len, 300);

    // High tag number: [100] primitive = 0x9f 0x64, with length 2 and
    // content 0x01 0x02. header_len = 2 identifier + 1 length octet.
    let der = [0x9f, 0x64, 0x02, 0x01, 0x02];
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    assert_eq!(tree[0].tag_class, Asn1Class::Context);
    assert_eq!(tree[0].tag_number, 100);
    assert_eq!(tree[0].header_len, 3);
    assert_eq!(tree[0].value_len, 2);
    assert_eq!(tree[0].value, None);
    assert_eq!(tree[0].hex_preview.as_deref(), Some("0102"));
}

#[test]
fn malformed_content_stays_browsable_as_raw() {
    // NULL with content, invalid UTF-8 in a UTF8String, bad OID: the tree
    // still comes back, with the offending nodes as Raw hex blobs.
    let der = seq(&[&null_with_content(), &bad_utf8(), &bad_oid()]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let children = &tree[0].children;
    assert_eq!(children.len(), 3);
    match &children[0].value {
        Some(Asn1Value::Raw { hex }) => {
            assert_eq!(hex, "00");
        }
        other => panic!("expected Raw for NULL with content, got {other:?}"),
    }
    match &children[1].value {
        Some(Asn1Value::Raw { .. }) => {}
        other => panic!("expected Raw, got {other:?}"),
    }
    match &children[2].value {
        Some(Asn1Value::Raw { .. }) => {}
        other => panic!("expected Raw, got {other:?}"),
    }
}

fn null_with_content() -> Vec<u8> {
    tlv(0x05, &[0x00])
}

fn bad_utf8() -> Vec<u8> {
    tlv(0x0c, &[0xff, 0xfe, 0xfd])
}

/// OID with a truncated subidentifier (continuation bit never cleared).
fn bad_oid() -> Vec<u8> {
    tlv(0x06, &[0x2a, 0x86])
}

#[test]
fn negative_integer_rendering() {
    let der = seq(&[
        &integer(&[0xff]),
        &integer(&[0x80]),
        &integer(&[0x01, 0x00]),
    ]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let children = &tree[0].children;
    match node_value(&children[0]) {
        Asn1Value::Integer { value, hex } => {
            assert_eq!(value, "-1");
            assert_eq!(hex, "ff");
        }
        other => panic!("expected INTEGER, got {other:?}"),
    }
    match node_value(&children[1]) {
        Asn1Value::Integer { value, .. } => assert_eq!(value, "-128"),
        other => panic!("expected INTEGER, got {other:?}"),
    }
    match node_value(&children[2]) {
        Asn1Value::Integer { value, .. } => assert_eq!(value, "256"),
        other => panic!("expected INTEGER, got {other:?}"),
    }
}

#[test]
fn empty_sequence_and_bit_string() {
    let der = seq(&[&tlv(0x30, &[]), &tlv(0x03, &[0x00, 0xab, 0xcd])]);
    let tree = parse_der_tree(&der, DEFAULT_MAX_DEPTH).unwrap();
    let empty_seq = &tree[0].children[0];
    assert!(empty_seq.constructed);
    assert!(empty_seq.children.is_empty());
    let bits = &tree[0].children[1];
    match node_value(bits) {
        Asn1Value::BitString { hex, unused_bits } => {
            assert_eq!(hex, "abcd");
            assert_eq!(*unused_bits, 0);
        }
        other => panic!("expected BIT STRING, got {other:?}"),
    }
}

#[test]
fn oid_table_lookup() {
    assert_eq!(oid_name("2.5.29.17"), Some("subjectAltName"));
    assert_eq!(oid_name("2.5.29.15"), Some("keyUsage"));
    assert_eq!(oid_name("2.5.29.19"), Some("basicConstraints"));
    assert_eq!(oid_name("1.2.840.10045.2.1"), Some("ecPublicKey"));
    assert_eq!(oid_name("1.3.101.112"), Some("Ed25519"));
    assert_eq!(oid_name("9.9.9.9"), None);
}

#[test]
fn error_displays_are_reasonable() {
    // Sanity-check that OperationError round-trips through serde for IPC.
    let err: OperationError = parse_der_tree(&[0x30, 0x80], DEFAULT_MAX_DEPTH).unwrap_err();
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["kind"], "decode");
    assert!(json["message"].as_str().unwrap().contains("indefinite"));
}
