//! CyberCipher CLI. Shares the engine (and therefore every operation) with
//! the GUI; no algorithm code is duplicated.

use clap::{Parser, Subcommand};
use cybercipher_core::{ExecutionContext, ParamMap, ParamValue, Value};
use cybercipher_engine::{RecipeEngine, RecipeV1, RunMode};
use std::io::Read;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "cybercipher",
    version,
    about = "CyberCipher — crypto, decode, analyze, solve (local-first CTF workbench)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List registered operations.
    Ops,
    /// Run one operation on input.
    Run {
        /// Operation id, e.g. from-base64.
        #[arg(short, long)]
        op: String,
        /// Parameters as key=value (repeated). Values parse as bool/int then fall back to string.
        #[arg(short, long = "param")]
        params: Vec<String>,
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
    /// Bounded explainable automatic decoding.
    Auto {
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
    /// Execute a recipe file (JSON, format v1) on input.
    Recipe {
        /// Recipe JSON file path.
        recipe: String,
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let registry = Arc::new(cybercipher_engine::default_registry());
    let engine = RecipeEngine::new(registry.clone());

    match cli.command {
        Command::Ops => {
            for info in registry.info() {
                println!("{:<22} {:<16} {}", info.id, info.category.name(), info.name);
            }
        }
        Command::Run { op, params, input } => {
            let operation = registry.get(&op).unwrap_or_else(|| {
                eprintln!("error: unknown operation `{op}` — use `cybercipher ops` to list");
                std::process::exit(2);
            });
            let mut map = ParamMap::new();
            for p in &params {
                let (k, v) = p.split_once('=').unwrap_or_else(|| {
                    eprintln!("error: parameter `{p}` is not key=value");
                    std::process::exit(2);
                });
                map.insert(k, parse_param(v));
            }
            let data = read_input(&input);
            let value = Value::from_bytes(data);
            match operation.execute(&value, &map, &ExecutionContext::new()) {
                Ok(out) => print_value(&out),
                Err(e) => {
                    eprintln!(
                        "error [{}]: {e}",
                        serde_json::to_string(&e.kind).unwrap_or_default()
                    );
                    if let Some(d) = &e.details {
                        eprintln!("details: {d}");
                    }
                    std::process::exit(1);
                }
            }
        }
        Command::Auto { input } => {
            let data = read_input(&input);
            let candidates = cybercipher_engine::auto_decode(
                &registry,
                &data,
                &cybercipher_core::ExecutionContext::new(),
            );
            if candidates.is_empty() {
                println!("no plausible decoding found");
            }
            for (i, c) in candidates.iter().enumerate() {
                println!(
                    "#{} score {:.2}{} path: {}",
                    i + 1,
                    c.score,
                    if c.confident { " (confident)" } else { "" },
                    c.path.join(" -> ")
                );
                for e in &c.evidence {
                    println!("    + {e}");
                }
                let head: String = c.preview.chars().take(120).collect();
                println!("    preview: {head:?}");
            }
        }
        Command::Recipe { recipe, input } => {
            let text = read_input(&recipe);
            let recipe: RecipeV1 = serde_json::from_slice(&text).unwrap_or_else(|e| {
                eprintln!("error: recipe file is not valid JSON: {e}");
                std::process::exit(2);
            });
            let data = read_input(&input);
            let report = engine.execute(
                &recipe,
                Value::from_bytes(data),
                RunMode::Manual,
                &ExecutionContext::new(),
            );
            match report {
                Ok(report) => {
                    for stage in &report.stages {
                        let status = format!("{:?}", stage.status).to_lowercase();
                        println!(
                            "[{status}] {:<18} {} · {} µs",
                            stage.op_id, stage.kind, stage.duration_us
                        );
                    }
                    if let Some(e) = &report.error {
                        eprintln!(
                            "error [{}]: {e}",
                            serde_json::to_string(&e.kind).unwrap_or_default()
                        );
                        if let Some(d) = &e.details {
                            eprintln!("details: {d}");
                        }
                        std::process::exit(1);
                    }
                    if let Some(out) = &report.output {
                        print_value(out);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

fn parse_param(v: &str) -> ParamValue {
    if v == "true" {
        return ParamValue::Bool(true);
    }
    if v == "false" {
        return ParamValue::Bool(false);
    }
    if let Ok(i) = v.parse::<i64>() {
        return ParamValue::Int(i);
    }
    if let Ok(f) = v.parse::<f64>() {
        if v.contains('.') {
            return ParamValue::Float(f);
        }
    }
    ParamValue::Str(v.to_string())
}

/// Read input: `-` is stdin, an existing path is a file, anything else is a
/// literal string.
fn read_input(spec: &str) -> Vec<u8> {
    if spec == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
            eprintln!("error reading stdin: {e}");
            std::process::exit(2);
        });
        return buf;
    }
    let path = std::path::Path::new(spec);
    if path.is_file() {
        return std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("error reading `{spec}`: {e}");
            std::process::exit(2);
        });
    }
    spec.as_bytes().to_vec()
}

fn print_value(v: &Value) {
    match v {
        Value::Text(t) => println!("{t}"),
        Value::Bytes(b) => {
            // Bytes print as lowercase hex on one line — pipe-friendly.
            let mut out = String::with_capacity(b.len() * 2);
            for byte in b {
                out.push_str(&format!("{byte:02x}"));
            }
            println!("{out}");
        }
        Value::Json(j) => println!("{j:#}"),
        Value::Integer(i) => println!("{i}"),
        Value::IntegerList(l) => println!(
            "{}",
            l.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::List(items) => {
            for item in items {
                println!("{item:?}");
            }
        }
        Value::Null => {}
    }
}
