//! Inspection operations: entropy analysis and strings extraction. These feed
//! both interactive use and the Auto Decode scoring layer.

use crate::helpers::{input_bytes, p_int, spec};
use cybercipher_core::prelude::*;

fn entropy_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Entropy")?;
    let mut counts = [0u64; 256];
    for &b in bytes.iter() {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let entropy = cybercipher_core::util::shannon_entropy(bytes.as_ref());
    let printable = cybercipher_core::util::printable_ratio(bytes.as_ref());
    let unique = counts.iter().filter(|&&c| c > 0).count();
    let mut top: Vec<(u8, u64)> = counts
        .iter()
        .enumerate()
        .filter(|(_, &c)| c > 0)
        .map(|(b, &c)| (b as u8, c))
        .collect();
    top.sort_by_key(|a| std::cmp::Reverse(a.1));
    let top_json: Vec<serde_json::Value> = top
        .into_iter()
        .take(16)
        .map(|(b, c)| {
            serde_json::json!({
                "byte": format!("{b:02x}"),
                "count": c,
                "pct": (c as f64 / n * 1000.0).round() / 10.0,
            })
        })
        .collect();
    Ok(Value::Json(serde_json::json!({
        "length": bytes.len(),
        "entropy_bits_per_byte": (entropy * 10000.0).round() / 10000.0,
        "printable_ratio": (printable * 10000.0).round() / 10000.0,
        "unique_bytes": unique,
        "top_bytes": top_json,
    })))
}

fn strings_op(v: &Value, map: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Strings")?;
    let min_len = map.require_int("min_length", 1, 4096)? as usize;
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for &b in bytes.iter() {
        ctx.check()?;
        if (0x20..=0x7E).contains(&b) {
            current.push(b as char);
        } else if !current.is_empty() {
            if current.len() >= min_len {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= min_len {
        out.push(current);
    }
    Ok(Value::Text(out.join("\n")))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::{Analysis as A, Utility as U},
        ValueKind::{Bytes as B, Json as J, Text as T},
    };

    reg.add_simple(spec(
        "entropy", "Entropy",
        "Reports Shannon entropy, printable ratio, unique byte count, and the most frequent bytes.",
        A, &[B, T], J, CostClass::Instant, false,
        vec![],
        &["analysis", "ctf"], &["shannon", "randomness"],
        "Shannon (1948), A Mathematical Theory of Communication", "Analytic hand-checked cases",
    ), entropy_op);

    reg.add_simple(
        spec(
            "strings",
            "Strings",
            "Extracts printable ASCII runs of at least the minimum length.",
            U,
            &[B, T],
            T,
            CostClass::Interactive,
            false,
            vec![p_int(
                "min_length",
                "Minimum length",
                4,
                "Minimum run length to report.",
            )],
            &["utility", "ctf", "forensics"],
            &["extract strings"],
            "Behavior modeled on POSIX `strings`",
            "Round-trip hand-checked cases",
        ),
        strings_op,
    );
}
