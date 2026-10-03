//! Stream cipher operations: Salsa20 and XSalsa20 (RustCrypto `salsa20`
//! crate), HC-256 (RustCrypto `hc-256`), Rabbit (RustCrypto `rabbit`) and
//! ZUC-128 (`zuc` crate, GB/T 33133). Encryption and decryption are the
//! same operation — applying the keystream — so each cipher exposes a
//! single op, mirroring RC4.

use cipher::{KeyIvInit, StreamCipher};
use cybercipher_core::prelude::*;

use crate::helpers::{decode_material, input_bytes, p_enc, p_text};

const STREAM_TAGS: &[&str] = &["crypto", "stream"];

type StreamApply = fn(&[u8], &[u8], &[u8]) -> OpResult<Vec<u8>>;

#[allow(clippy::too_many_arguments)]
fn stream_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    key_len: usize,
    nonce_len: usize,
    aliases: &'static [&'static str],
    standard: &'static str,
    implementation: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    let params = vec![
        p_text(
            "key",
            "Key",
            "",
            Box::leak(format!("{key_len}-byte key after decoding.").into_boxed_str()),
        ),
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
            implementation,
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

/// HC-256 (Wu, FSE 2004): 32-byte key, 32-byte IV.
fn hc256_apply(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    apply_stream::<hc_256::Hc256>(key, nonce, data)
}

/// Rabbit (RFC 4503): 16-byte key, 8-byte IV.
fn rabbit_apply(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    apply_stream::<rabbit::Rabbit>(key, nonce, data)
}

/// ZUC-128 (GB/T 33133 / 3GPP EEA3 core): 16-byte key, 16-byte IV.
/// The keystream generator follows the standard work-mode semantics (the
/// output of the transition cycle is discarded), matching the 3GPP
/// Implementor's Test Data and the GB/T 33133.1-2016 annex C tables.
fn zuc_apply(key: &[u8], nonce: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    let key: [u8; 16] = key.try_into().expect("checked 16-byte key");
    let iv: [u8; 16] = nonce.try_into().expect("checked 16-byte iv");
    let mut buf = data.to_vec();
    let bitlen = buf.len() * 8;
    zuc::zuc128::zuc128_xor_inplace(&key, &iv, &mut buf, bitlen);
    Ok(buf)
}

fn stream_run(
    name: &'static str,
    key_len: usize,
    nonce_len: usize,
    apply: StreamApply,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        if key.len() != key_len {
            return Err(stream_material_error(
                &format!("{name} key"),
                "key",
                key_len,
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
            32,
            8,
            &["salsa20-crypt"],
            "Salsa20 (D. J. Bernstein; eSTREAM Profile 1)",
            "RustCrypto `salsa20` crate",
            "ECRYPT eSTREAM verified test vectors",
        ),
        stream_run("Salsa20", 32, 8, salsa20_apply),
    );

    reg.add_simple(
        stream_spec(
            "xsalsa20",
            "XSalsa20",
            "Applies the XSalsa20 keystream — Salsa20 with a 24-byte extended nonce (HSalsa20 key derivation); encryption and decryption are identical.",
            32,
            24,
            &["xsalsa20-crypt"],
            "XSalsa20 (D. J. Bernstein, \"Extending the Salsa20 Nonce\")",
            "RustCrypto `salsa20` crate",
            "XSalsa20 reference test vectors",
        ),
        stream_run("XSalsa20", 32, 24, xsalsa20_apply),
    );

    reg.add_simple(
        stream_spec(
            "hc256-encrypt",
            "HC-256",
            "Applies the HC-256 keystream (Wu, FSE 2004; eSTREAM portfolio); encryption and decryption are identical. 32-byte key, 32-byte nonce (IV).",
            32,
            32,
            &["hc256", "hc256-decrypt", "hc-256"],
            "HC-256 (Hongjun Wu, FSE 2004; eSTREAM Portfolio)",
            "RustCrypto `hc-256` crate",
            "HC-256 paper test vectors (Wu 2004, Appendix B)",
        ),
        stream_run("HC-256", 32, 32, hc256_apply),
    );

    reg.add_simple(
        stream_spec(
            "rabbit-encrypt",
            "Rabbit",
            "Applies the Rabbit keystream (RFC 4503, eSTREAM portfolio); encryption and decryption are identical. 16-byte key, 8-byte nonce (IV).",
            16,
            8,
            &["rabbit", "rabbit-decrypt"],
            "Rabbit (RFC 4503; eSTREAM Portfolio)",
            "RustCrypto `rabbit` crate",
            "RFC 4503 Appendix A.2 test vectors",
        ),
        stream_run("Rabbit", 16, 8, rabbit_apply),
    );

    reg.add_simple(
        stream_spec(
            "zuc-encrypt",
            "ZUC-128",
            "Applies the ZUC-128 keystream (GB/T 33133; the core of 3GPP 128-EEA3); encryption and decryption are identical. 16-byte key, 16-byte nonce (IV).",
            16,
            16,
            &["zuc", "zuc128", "eea3"],
            "ZUC-128 (GB/T 33133.1-2016; 3GPP TS 35.221)",
            "`zuc` crate (zuc128_xor_inplace)",
            "3GPP TS 35.221 Document 3 test sets 1-3",
        ),
        stream_run("ZUC-128", 16, 16, zuc_apply),
    );
}
