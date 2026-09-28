//! Operation metadata: everything the GUI needs to generate parameter forms,
//! search results, status badges, and provenance displays — without
//! hardcoding algorithm-specific forms in React.

use crate::param::ParamValue;
use crate::value::ValueKind;
use serde::{Deserialize, Serialize};

/// Top-level operation category. Drives the operations panel grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Encoding,
    ByteOperation,
    Crypto,
    Hash,
    Mac,
    Kdf,
    PublicKey,
    Classical,
    Analysis,
    Compression,
    Serialization,
    File,
    Utility,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Encoding => "Encoding",
            Category::ByteOperation => "Byte Operations",
            Category::Crypto => "Crypto",
            Category::Hash => "Hash",
            Category::Mac => "MAC",
            Category::Kdf => "KDF / Password",
            Category::PublicKey => "Public Key",
            Category::Classical => "Classical",
            Category::Analysis => "Analysis",
            Category::Compression => "Compression",
            Category::Serialization => "Serialization",
            Category::File => "File / CTF",
            Category::Utility => "Utility",
        }
    }
}

/// How expensive an operation is. Drives Auto Bake behavior: only `Instant`
/// and `Interactive` operations run automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostClass {
    /// Runs automatically with no debounce concern (encode/decode, byte ops).
    Instant,
    /// Runs automatically with debounce (compression, larger transforms).
    Interactive,
    /// Manual Bake by default (KDFs, big brute force).
    Heavy,
    /// Explicit Run (solvers, lattice reduction, factoring).
    Solver,
    /// Explicit Run + external dependency check.
    External,
}

/// Security classification. CyberCipher never hides broken primitives from
/// CTF users, but always labels them honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    Modern,
    Legacy,
    Broken,
    Hazmat,
    Neutral,
}

impl Security {
    pub fn label(self) -> &'static str {
        match self {
            Security::Modern => "Modern",
            Security::Legacy => "Legacy",
            Security::Broken => "Broken",
            Security::Hazmat => "CTF/Hazmat",
            Security::Neutral => "",
        }
    }
}

/// Where an algorithm's definition, implementation, and test vectors come
/// from. First-class metadata, exposed in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Authoritative standard or specification (e.g. "NIST FIPS 197").
    pub standard: &'static str,
    /// Implementation note (e.g. "RustCrypto `aes` crate").
    pub implementation: &'static str,
    /// Test vector source (e.g. "NIST AESAVS").
    pub test_vectors: &'static str,
}

impl Provenance {
    /// Default provenance for CyberCipher-native utilities.
    pub const PROJECT: Provenance = Provenance {
        standard: "CyberCipher project",
        implementation: "CyberCipher native Rust",
        test_vectors: "CyberCipher unit tests",
    };
}

/// The type of one operation parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    /// Single-line string (keys, separators, patterns).
    Text,
    /// Multi-line string (long keys, text blocks).
    TextArea,
    /// Integer with optional range validation done by the operation.
    Integer,
    /// Floating point number.
    Float,
    /// Checkbox.
    Boolean,
    /// Dropdown over fixed options (value/label pairs).
    Options,
    /// Dropdown over key/data interpretation encodings
    /// (utf8/hex/base64/decimal/...).
    Encoding,
}

/// A fixed option for `ParamKind::Options` / `Encoding` dropdowns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ParamOption {
    pub value: &'static str,
    pub label: &'static str,
}

/// Default value of a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamDefault {
    Str(&'static str),
    Int(i64),
    Bool(bool),
    Float(f64),
}

impl ParamDefault {
    pub fn to_param_value(self) -> ParamValue {
        match self {
            ParamDefault::Str(s) => ParamValue::Str(s.to_string()),
            ParamDefault::Int(i) => ParamValue::Int(i),
            ParamDefault::Bool(b) => ParamValue::Bool(b),
            ParamDefault::Float(f) => ParamValue::Float(f),
        }
    }
}

/// One parameter of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ParamSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: ParamKind,
    pub default: ParamDefault,
    #[serde(default)]
    pub optional: bool,
    /// Short help text shown under the field.
    #[serde(default)]
    pub hint: &'static str,
    /// Options for `Options`/`Encoding` kinds.
    #[serde(default)]
    pub options: &'static [ParamOption],
}

/// Full static metadata for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct OperationSpec {
    /// Stable machine identifier, e.g. `from-base64`.
    pub id: &'static str,
    /// Human display name, e.g. `From Base64`.
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    /// Accepted input kinds. `Text` input accepts coerced `Bytes` and
    /// vice versa; see `Value::as_bytes`.
    pub input_kinds: &'static [ValueKind],
    pub output_kind: ValueKind,
    pub params: &'static [ParamSpec],
    pub cost: CostClass,
    pub security: Security,
    /// True when the same input and parameters always produce the same output.
    pub deterministic: bool,
    /// True when a sibling operation inverts this one.
    pub reversible: bool,
    /// Search aliases, e.g. `["b64"]` for Base64, `["rijndael"]` for AES.
    pub aliases: &'static [&'static str],
    /// Free-form tags, e.g. `["ctf", "encoding"]`.
    pub tags: &'static [&'static str],
    pub provenance: Provenance,
}
