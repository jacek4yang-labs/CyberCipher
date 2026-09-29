//! Stream cipher operations: Salsa20 and XSalsa20 (RustCrypto `salsa20`
//! crate). Encryption and decryption are the same operation — applying the
//! keystream — so each cipher exposes a single op, mirroring RC4.

use cipher::{KeyIvInit, StreamCipher};
use cybercipher_core::prelude::*;

use crate::helpers::{decode_material, input_bytes, p_enc, p_text};

const STREAM_TAGS: &[&str] = &["crypto", "stream"];

type StreamApply = fn(&[u8], &[u8], &[u8]) -> OpResult<Vec<u8>>;

fn stream_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    nonce_len: usize,
    aliases: &'static [&'static str],
    standard: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    let params = vec![
        p_text("key", "Key", "", "32-byte key after decoding."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_text(
            "nonce",
            "Nonce",
            "",
            Box::leak(format!("{nonce_len}-byte nonce after decoding.").into_boxed_str()),
        ),
        p_enc("nonce_encoding", "Nonce encoding", "hex", ""),
    ];
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Bytes,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security: Security::Modern,
        deterministic: true,
        reversible: true,
        aliases,
        tags: STREAM_TAGS,
        provenance: Provenance {
            standard,
            implementation: "RustCrypto `salsa20` crate",
            test_vectors: vectors,
        },
    }))
}

fn stream_material_error(
    what: &str,
    param: &str,
    expected: usize,
    actual: usize,
) -> OperationError {
    OperationError::key(format!(
        "{what} must be {expected} bytes after decoding, got {actual} bytes"
    ))
    .with_parameter(param)
    .with_expected(format!("{expected} bytes"))
    .with_actual(format!("{actual} bytes"))
}

/// Shared body for Salsa20/XSalsa20: XOR the input with the keystream.
fn apply_stream<C>(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: KeyIvInit + StreamCipher,
{
    let mut buf = data.to_vec();
    let mut cipher = C::new_from_slices(key, nonce)
        .map_err(|_| OperationError::internal("stream cipher rejected key/nonce lengths"))?;
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

fn salsa20_apply(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    apply_stream::<salsa20::Salsa20>(key, nonce, data)
}

fn xsalsa20_apply(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    apply_stream::<salsa20::XSalsa20>(key, nonce, data)
}

fn stream_run(
    name: &'static str,
    nonce_len: usize,
    apply: StreamApply,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        if key.len() != 32 {
            return Err(stream_material_error(
                &format!("{name} key"),
                "key",
                32,
                key.len(),
            ));
        }
        let nonce = decode_material(map, "nonce", "nonce_encoding", "nonce")?;
        if nonce.len() != nonce_len {
            return Err(stream_material_error(
                &format!("{name} nonce"),
                "nonce",
                nonce_len,
                nonce.len(),
            ));
        }
        Ok(Value::Bytes(apply(&key, &nonce, bytes.as_ref())?))
    }
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    reg.add_simple(
        stream_spec(
            "salsa20",
            "Salsa20",
            "Applies the Salsa20 keystream (Bernstein, eSTREAM); encryption and decryption are identical. 32-byte key, 8-byte nonce.",
            8,
            &["salsa20-crypt"],
            "Salsa20 (D. J. Bernstein; eSTREAM Profile 1)",
            "ECRYPT eSTREAM verified test vectors",
        ),
        stream_run("Salsa20", 8, salsa20_apply),
    );

    reg.add_simple(
        stream_spec(
            "xsalsa20",
            "XSalsa20",
            "Applies the XSalsa20 keystream — Salsa20 with a 24-byte extended nonce (HSalsa20 key derivation); encryption and decryption are identical.",
            24,
            &["xsalsa20-crypt"],
            "XSalsa20 (D. J. Bernstein, \"Extending the Salsa20 Nonce\")",
            "XSalsa20 reference test vectors",
        ),
        stream_run("XSalsa20", 24, xsalsa20_apply),
    );
}
