//! Message authentication codes outside the HMAC family: CMAC (NIST
//! SP 800-38B), GMAC (SP 800-38D, GCM with empty plaintext) and Poly1305
//! (RFC 8439). All operations return lowercase hex tags.

use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use cmac::Cmac;
use cybercipher_codec::decode_input;
use cybercipher_core::prelude::*;
use des::TdesEde2;
use des::TdesEde3;

use crate::helpers::{hex, p_enc, p_opts, p_text, p_text_opt};

const MAC_TAGS: &[&str] = &["crypto", "mac"];

#[allow(clippy::too_many_arguments)]
fn mac_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    params: Vec<ParamSpec>,
    security: Security,
    aliases: &'static [&'static str],
    standard: &'static str,
    implementation: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security,
        deterministic: true,
        reversible: false,
        aliases,
        tags: MAC_TAGS,
        provenance: Provenance {
            standard,
            implementation,
            test_vectors: vectors,
        },
    }))
}

fn key_len_error(what: &str, param: &str, expected: &str, actual: usize) -> OperationError {
    OperationError::key(format!(
        "{what} key must be {expected} bytes after decoding, got {actual} bytes"
    ))
    .with_parameter(param)
    .with_expected(format!("{expected} bytes"))
    .with_actual(format!("{actual} bytes"))
}

// ------------------------------------------------------------ CMAC ----

struct CmacChoice {
    label: &'static str,
    expected: usize,
    compute: fn(&[u8], &[u8]) -> OpResult<Vec<u8>>,
}

fn cmac_of<M>(key: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    M: cmac::Mac + cmac::KeyInit,
{
    let mut mac = <M as cmac::KeyInit>::new_from_slice(key)
        .map_err(|_| OperationError::internal("CMAC rejected the key length"))?;
    cmac::Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().as_slice().to_vec())
}

const CMAC_CHOICES: &[CmacChoice] = &[
    CmacChoice {
        label: "aes-128",
        expected: 16,
        compute: cmac_of::<Cmac<Aes128>>,
    },
    CmacChoice {
        label: "aes-192",
        expected: 24,
        compute: cmac_of::<Cmac<Aes192>>,
    },
    CmacChoice {
        label: "aes-256",
        expected: 32,
        compute: cmac_of::<Cmac<Aes256>>,
    },
    CmacChoice {
        label: "tdes-2",
        expected: 16,
        compute: cmac_of::<Cmac<TdesEde2>>,
    },
    CmacChoice {
        label: "tdes-3",
        expected: 24,
        compute: cmac_of::<Cmac<TdesEde3>>,
    },
    CmacChoice {
        label: "kuznyechik",
        expected: 32,
        compute: cmac_of::<Cmac<kuznyechik::Kuznyechik>>,
    },
    CmacChoice {
        label: "magma",
        expected: 32,
        compute: cmac_of::<Cmac<magma::Magma>>,
    },
];

fn cmac_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = crate::helpers::input_bytes(v, "CMAC")?;
    let key = crate::helpers::decode_material(map, "key", "key_encoding", "key")?;
    let choice_label = map.str_or("cipher", "aes-128");
    let choice = CMAC_CHOICES
        .iter()
        .find(|c| c.label == choice_label)
        .ok_or_else(|| {
            OperationError::invalid_param("cipher", format!("unknown CMAC cipher `{choice_label}`"))
        })?;
    if key.len() != choice.expected {
        return Err(key_len_error(
            "CMAC",
            "key",
            &choice.expected.to_string(),
            key.len(),
        ));
    }
    Ok(Value::Text(hex(&(choice.compute)(&key, bytes.as_ref())?)))
}

// ------------------------------------------------------------ GMAC ----

/// GMAC is GCM restricted to authenticated data (empty plaintext,
/// NIST SP 800-38D), so the tag is exactly the GCM tag of the empty
/// message with the AAD as associated data.
fn gmac_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let key = crate::helpers::decode_material(map, "key", "key_encoding", "key")?;
    let iv_raw = map.require_str("iv")?;
    let iv = decode_input(map.str_or("iv_encoding", "hex"), iv_raw)
        .map_err(|e| e.with_parameter("iv"))?;
    if iv.len() != 12 {
        return Err(key_len_error("GMAC IV", "iv", "12", iv.len()));
    }
    let aad_raw = map.str_or("aad", "");
    let aad = if aad_raw.is_empty() {
        Vec::new()
    } else {
        decode_input(map.str_or("aad_encoding", "hex"), aad_raw)
            .map_err(|e| e.with_parameter("aad"))?
    };

    let tag: Vec<u8> = match key.len() {
        16 => gmac_tag::<aes_gcm::Aes128Gcm>(&key, &iv, &aad)?,
        32 => gmac_tag::<aes_gcm::Aes256Gcm>(&key, &iv, &aad)?,
        n => {
            return Err(key_len_error("GMAC", "key", "16 / 32", n));
        }
    };
    Ok(Value::Text(hex(&tag)))
}

fn gmac_tag<C>(key: &[u8], iv: &[u8], aad: &[u8]) -> OpResult<Vec<u8>>
where
    C: aes_gcm::aead::AeadInPlace + aes_gcm::aead::KeyInit,
{
    let cipher = C::new_from_slice(key)
        .map_err(|_| OperationError::internal("GMAC rejected the key length"))?;
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut [])
        .map_err(|e| OperationError::internal(format!("GMAC computation failed: {e}")))?;
    Ok(tag.to_vec())
}

// -------------------------------------------------------- Poly1305 ----

fn poly1305_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = crate::helpers::input_bytes(v, "Poly1305")?;
    let key = crate::helpers::decode_material(map, "key", "key_encoding", "key")?;
    if key.len() != 32 {
        return Err(key_len_error("Poly1305", "key", "32", key.len()));
    }
    let key: [u8; 32] = key.try_into().expect("checked 32 bytes");
    use poly1305::universal_hash::KeyInit;
    let tag = poly1305::Poly1305::new(&poly1305::Key::from(key)).compute_unpadded(bytes.as_ref());
    Ok(Value::Text(hex(tag.as_slice())))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    // CMAC over the block ciphers RustCrypto supports directly.
    let cmac_ciphers: &'static [ParamOption] = &[
        ParamOption {
            value: "aes-128",
            label: "AES-128",
        },
        ParamOption {
            value: "aes-192",
            label: "AES-192",
        },
        ParamOption {
            value: "aes-256",
            label: "AES-256",
        },
        ParamOption {
            value: "tdes-2",
            label: "3DES (2-key)",
        },
        ParamOption {
            value: "tdes-3",
            label: "3DES (3-key)",
        },
        ParamOption {
            value: "kuznyechik",
            label: "Kuznyechik",
        },
        ParamOption {
            value: "magma",
            label: "Magma",
        },
    ];
    let cmac_params = vec![
        p_text(
            "key",
            "Key",
            "",
            "Key material; length must match the selected cipher.",
        ),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_opts(
            "cipher",
            "Cipher",
            "aes-128",
            cmac_ciphers,
            "Block cipher underneath CMAC (NIST SP 800-38B).",
        ),
    ];
    reg.add_simple(
        mac_spec(
            "cmac",
            "CMAC",
            "Computes CMAC (Cipher-based MAC, NIST SP 800-38B) over the input with the selected block cipher. Output is lowercase hex.",
            cmac_params,
            Security::Modern,
            &["cmac-aes", "aes-cmac"],
            "NIST SP 800-38B",
            "RustCrypto `cmac` crate",
            "NIST SP 800-38B examples / CAVP / GOST R 34.13-2015 vectors",
        ),
        cmac_run,
    );

    // GMAC (SP 800-38D): GCM restricted to associated data.
    let gmac_params = vec![
        p_text("key", "Key", "", "AES key: 16 or 32 bytes after decoding."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_text(
            "iv",
            "IV",
            "",
            "96-bit (12-byte) IV; GMAC's keyed-IV parameter J0.",
        ),
        p_enc("iv_encoding", "IV encoding", "hex", ""),
        p_text_opt(
            "aad",
            "AAD",
            "",
            "Additional authenticated data (the GMAC message).",
        ),
        p_enc("aad_encoding", "AAD encoding", "hex", ""),
    ];
    reg.add_simple(
        mac_spec(
            "gmac",
            "GMAC",
            "Computes GMAC (NIST SP 800-38D): GCM restricted to authenticated data. The tag equals the AES-GCM tag of an empty plaintext with the given AAD. Output is lowercase hex.",
            gmac_params,
            Security::Modern,
            &["gcm-mac", "gmac-aes"],
            "NIST SP 800-38D",
            "RustCrypto `aes-gcm` crate (AAD-only GCM)",
            "SP 800-38D GCM/GMAC test cases",
        ),
        gmac_run,
    );

    // Poly1305 (one-shot, RFC 8439 semantics).
    let poly1305_params = vec![
        p_text(
            "key",
            "Key",
            "",
            "32-byte one-time key (r || s) per RFC 8439.",
        ),
        p_enc("key_encoding", "Key encoding", "hex", ""),
    ];
    reg.add_simple(
        mac_spec(
            "poly1305",
            "Poly1305",
            "Computes the Poly1305 one-time authenticator (RFC 8439). The 32-byte key must never be reused for another message. Output is lowercase hex.",
            poly1305_params,
            Security::Modern,
            &["poly1305-mac"],
            "Poly1305 (Bernstein); RFC 8439",
            "RustCrypto `poly1305` crate",
            "RFC 8439 section 2.5.2 test vector",
        ),
        poly1305_run,
    );
}
