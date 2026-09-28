import { useState } from "react";
import { useStore } from "../store";
import { copyAs, formatEntropy, formatSize, payloadToText, payloadBytes, payloadSize } from "../format";

export function DataPanel() {
  const inputText = useStore((s) => s.inputText);
  const inputEncoding = useStore((s) => s.inputEncoding);
  const setInputText = useStore((s) => s.setInputText);
  const setInputEncoding = useStore((s) => s.setInputEncoding);
  const output = useStore((s) => s.output);
  const inputStats = useStore((s) => s.inputStats);
  const outputToInput = useStore((s) => s.outputToInput);
  const swapInputOutput = useStore((s) => s.swapInputOutput);
  const [outView, setOutView] = useState<"text" | "hex">("text");
  const [copied, setCopied] = useState<string | null>(null);

  const doCopy = async (format: string) => {
    if (!output) return;
    const text = copyAs(output, format);
    await navigator.clipboard.writeText(text);
    setCopied(format);
    setTimeout(() => setCopied(null), 1200);
  };

  const outputText = output ? payloadToText(output, outView) : "";
  const outSize = output ? payloadSize(output) : 0;
  const outEntropy = output && (output.kind === "text" || output.kind === "bytes") ? output.entropy : null;
  const isUtf8 = output?.kind !== "bytes" || output.is_utf8;

  return (
    <div className="data-panel">
      <div className="data-half input-half">
        <div className="panel-head">
          <span>Input</span>
          <div className="panel-tools">
            <select
              value={inputEncoding}
              onChange={(e) => setInputEncoding(e.target.value as typeof inputEncoding)}
              title="How the input text is interpreted before the recipe runs"
            >
              <option value="utf8">UTF-8</option>
              <option value="hex">Hex</option>
              <option value="base64">Base64</option>
              <option value="decimal">Decimal</option>
            </select>
            <span className="stats">
              {inputStats
                ? `${formatSize(inputStats.size)} · H ${formatEntropy(inputStats.entropy)} · ${Math.round(inputStats.printable_ratio * 100)}% printable`
                : ""}
            </span>
          </div>
        </div>
        <textarea
          className="data-textarea"
          spellCheck={false}
          placeholder="Paste data to analyze…"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
        />
      </div>
      <div className="data-divider" />
      <div className="data-half output-half">
        <div className="panel-head">
          <span>Output</span>
          <div className="panel-tools">
            {outEntropy !== null && (
              <span className="stats">
                {formatSize(outSize)} · H {formatEntropy(outEntropy)}
                {!isUtf8 && output?.kind === "bytes" && " · not UTF-8"}
              </span>
            )}
            <select value={outView} onChange={(e) => setOutView(e.target.value as "text" | "hex")}>
              <option value="text">Text</option>
              <option value="hex">Hexdump</option>
            </select>
            <button className="tool-btn" onClick={outputToInput} title="Send output to input">
              ↑ input
            </button>
            <button className="tool-btn" onClick={swapInputOutput} title="Swap input and output">
              ⇄
            </button>
            <select
              value=""
              onChange={(e) => void doCopy(e.target.value)}
              title="Copy output as…"
              className={copied ? "copied" : ""}
            >
              <option value="">{copied ? `copied ${copied} ✓` : "copy as…"}</option>
              <option value="utf8">UTF-8 text</option>
              <option value="hex">hex</option>
              <option value="hex-spaced">hex (spaced)</option>
              <option value="base64">Base64</option>
              <option value="python">Python bytes</option>
              <option value="c-array">C array</option>
              <option value="decimal">decimal list</option>
              <option value="integer">integer</option>
            </select>
          </div>
        </div>
        <pre className="data-output" spellCheck={false}>
          {outputText || <span className="dim">Output appears here after baking.</span>}
        </pre>
      </div>
    </div>
  );
}

export function flagHighlights(outputText: string): string | null {
  // Quick flag pattern sniffing for the status bar (CTF convenience).
  const m = outputText.match(/(?:flag|ctf|picoCTF|HTB)\{[^}\n]{4,120}\}/i);
  return m ? m[0] : null;
}

export function useOutputFlag(): string | null {
  const output = useStore((s) => s.output);
  if (!output) return null;
  const bytes = payloadBytes(output);
  if (!bytes) return null;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 1024 * 1024));
  return flagHighlights(text);
}
