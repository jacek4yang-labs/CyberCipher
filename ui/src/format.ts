import type { ValuePayload } from "./api";

const HEX_DISPLAY_LIMIT = 256 * 1024;

export function bytesFromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes: Uint8Array, separator = ""): string {
  const parts: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    parts[i] = bytes[i].toString(16).padStart(2, "0");
  }
  return parts.join(separator);
}

export function toHexdump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.subarray(off, off + 16);
    const hexParts: string[] = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        hexParts.push(chunk[i].toString(16).padStart(2, "0"));
        const c = chunk[i];
        ascii += c >= 0x20 && c <= 0x7e ? String.fromCharCode(c) : ".";
      } else {
        hexParts.push("  ");
      }
    }
    lines.push(
      `${off.toString(16).padStart(8, "0")}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts
        .slice(8)
        .join(" ")}  |${ascii}|`,
    );
  }
  return lines.join("\n");
}

/** Render a payload as display text for the output pane. */
export function payloadToText(p: ValuePayload, view: "text" | "hex"): string {
  switch (p.kind) {
    case "text":
      return view === "hex"
        ? hexOfUtf8(p.text)
        : p.text;
    case "bytes": {
      const bytes = bytesFromBase64(p.base64);
      return view === "hex" ? toHexdump(bytes) : p.text_lossy;
    }
    case "json":
      return JSON.stringify(p.value, null, 2);
    case "integer_list":
      return (
        p.items.join(", ") +
        (p.count > p.items.length ? `, … (+${p.count - p.items.length} more)` : "")
      );
    case "list":
      return (
        p.preview.join("\n") +
        (p.count > p.preview.length ? `\n… (+${p.count - p.preview.length} more)` : "")
      );
    case "null":
      return "";
  }
}

function hexOfUtf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > HEX_DISPLAY_LIMIT) return "(output too large for hex view)";
  return toHexdump(bytes);
}

export function payloadBytes(p: ValuePayload): Uint8Array | null {
  switch (p.kind) {
    case "text":
      return new TextEncoder().encode(p.text);
    case "bytes":
      return bytesFromBase64(p.base64);
    default:
      return null;
  }
}

export function payloadSize(p: ValuePayload): number {
  switch (p.kind) {
    case "text":
      return p.size;
    case "bytes":
      return p.size;
    case "json":
      return p.size;
    case "integer_list":
      return p.count;
    case "list":
      return p.count;
    case "null":
      return 0;
  }
}

/** Copy-as formatters for the output bytes (CTF conveniences). */
export function copyAs(p: ValuePayload, format: string): string {
  const bytes = payloadBytes(p);
  if (!bytes) {
    if (p.kind === "json") return JSON.stringify(p.value, null, 2);
    if (p.kind === "text") return p.text;
    return "";
  }
  switch (format) {
    case "hex":
      return toHex(bytes);
    case "hex-spaced":
      return toHex(bytes, " ");
    case "base64":
      return p.kind === "bytes" ? p.base64 : btoa(String.fromCharCode(...bytes));
    case "python":
      return `b"${toHexEscaped(bytes)}"`;
    case "c-array":
      return `{${Array.from(bytes, (b) => `0x${b.toString(16).padStart(2, "0")}`).join(", ")}}`;
    case "decimal":
      return Array.from(bytes).join(" ");
    case "integer": {
      if (bytes.length === 0) return "0";
      if (bytes.length > 4096) return "(too large for integer interpretation)";
      let hex = "";
      for (const b of bytes) hex += b.toString(16).padStart(2, "0");
      return BigInt("0x" + hex).toString(10);
    }
    case "utf8":
      return p.kind === "bytes" ? p.text_lossy : new TextDecoder().decode(bytes);
    default:
      return "";
  }
}

function toHexEscaped(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    if (b >= 0x20 && b <= 0x7e && c !== '"' && c !== "\\") out += c;
    else out += `\\x${b.toString(16).padStart(2, "0")}`;
  }
  return out;
}

export function formatEntropy(e: number): string {
  return e.toFixed(3);
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

export function formatDuration(us: number): string {
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(2)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}
