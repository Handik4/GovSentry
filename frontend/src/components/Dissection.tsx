import { VERDICT_GLYPH, VERDICT_LABEL } from "../lib/copy";
import type { ArgumentWord, Classification, Disassembly } from "../lib/types";
import { VERDICT_GLOW, VERDICT_TEXT } from "../lib/verdictStyle";

/** Top-level parameter types from a signature like "mint(address,uint256)". */
function paramTypes(signature: string): string[] | null {
  const open = signature.indexOf("(");
  if (signature === "UNKNOWN" || open < 0) return null;
  const inner = signature.slice(open + 1, -1);
  if (!inner) return [];
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of inner) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out.map((t) => t.trim());
}

/** One argument rendered as a typed literal. Only static head words line up
 *  with declared types; otherwise show the numeric reading plus an address guess. */
function Literal({ word, type }: { word: ArgumentWord; type: string | undefined }) {
  if (type === "address" && word.as_address) return <span className="break-all text-sky-300">{word.as_address}</span>;
  if (type === "bool") return <span className="text-cyan-300">{word.as_uint === "0" ? "false" : "true"}</span>;
  if (type && /^u?int\d*$/.test(type)) return <span className="break-all text-amber-200">{word.as_uint}</span>;
  if (type && /^bytes\d+$/.test(type)) return <span className="break-all text-violet-300">{word.word}</span>;
  return (
    <span className="break-all">
      <span className="text-amber-200">{word.as_uint}</span>
      {word.as_address && !type ? (
        <span className="text-muted">
          {" "}
          <span className="text-slate-500">/* or address </span>
          <span className="text-sky-300">{word.as_address}</span>
          <span className="text-slate-500"> */</span>
        </span>
      ) : null}
    </span>
  );
}

function Hex({ calldata }: { calldata: string }) {
  const body = calldata.replace(/^0x/, "");
  const words = body.slice(8).match(/.{1,64}/g) ?? [];
  return (
    <span className="break-all">
      <span className="text-slate-500">0x</span>
      <span className="rounded bg-sky-400/15 px-0.5 text-sky-300">{body.slice(0, 8)}</span>
      {words.map((w, i) => {
        const lead = w.match(/^0*/)?.[0] ?? "";
        return (
          <span key={i} className={i % 2 ? "text-slate-300" : "text-slate-200"}>
            <span className="hex-pad">{lead}</span>
            {w.slice(lead.length)}
          </span>
        );
      })}
    </span>
  );
}

function EditorBar({ file, tag }: { file: string; tag: string }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-sky-400/10 px-3 py-2">
      <span className="flex items-center gap-2">
        <span aria-hidden className="flex gap-1">
          <span className="size-2 rounded-full bg-slate-600" />
          <span className="size-2 rounded-full bg-slate-600" />
          <span className="size-2 rounded-full bg-slate-600" />
        </span>
        <span className="font-mono text-[11.5px] text-muted">{file}</span>
      </span>
      <span className="eyebrow !text-[10px]">{tag}</span>
    </div>
  );
}

/**
 * What a proposal claims, set against what its calldata executes, with the
 * verdict glowing between them.
 */
export function Dissection({
  prose,
  decoded,
  calldata,
  target,
  verdict,
  compact = false,
}: {
  prose: string;
  decoded: Disassembly | null;
  calldata?: string;
  target?: string;
  verdict: Classification | null;
  compact?: boolean;
}) {
  const fn = decoded?.signature ?? "";
  const name = fn === "UNKNOWN" ? "unknown_function" : fn.split("(")[0];
  const types = decoded ? paramTypes(decoded.signature) : null;

  return (
    <div className={`grid gap-3 ${compact ? "" : "xl:grid-cols-[1fr_auto_1fr]"}`}>
      <section className="code-block min-w-0 overflow-hidden" aria-label="Prose intent claim">
        <EditorBar file="proposal-description.md" tag="Prose Intent Claim" />
        <div className="p-4">
          {prose.trim() ? (
            <blockquote
              className={`border-l-2 border-sky-400/50 pl-3 font-display font-medium leading-snug text-ink ${
                compact ? "text-[16px]" : "text-lg sm:text-xl"
              } whitespace-pre-line`}
            >
              {prose.trim()}
            </blockquote>
          ) : (
            <p className="font-sans text-sm text-muted">The description voters were shown appears here.</p>
          )}
        </div>
      </section>

      <div
        className="glass-card flex items-center justify-center gap-3 px-4 py-2 xl:flex-col xl:px-3 xl:py-4"
        aria-label={verdict ? `Verdict: ${VERDICT_LABEL[verdict]}` : "No verdict yet"}
      >
        <span
          aria-hidden
          className={`font-display font-bold leading-none ${compact ? "text-4xl" : "text-5xl"} ${
            verdict ? `${VERDICT_TEXT[verdict]} ${VERDICT_GLOW[verdict]}` : "text-muted"
          }`}
        >
          {verdict ? VERDICT_GLYPH[verdict] : "?"}
        </span>
        <span className={`eyebrow ${compact ? "" : "xl:[writing-mode:vertical-rl] xl:rotate-180"} ${verdict ? VERDICT_TEXT[verdict] : ""}`}>
          {verdict ? VERDICT_LABEL[verdict] : "Not judged"}
        </span>
      </div>

      <section className="code-block min-w-0 overflow-hidden" aria-label="Decoded calldata actions">
        <EditorBar file="calldata.decoded" tag="Decoded Calldata Actions" />
        {decoded ? (
          <div className="space-y-3 p-4">
            <pre className="whitespace-pre-wrap break-words">
              <code>
                <span className="text-slate-500">
                  {"// selector "}
                  {decoded.selector}
                  {decoded.privileged ? " · " : ""}
                </span>
                {decoded.privileged ? <span className="font-semibold text-critical">PRIVILEGED</span> : null}
                {target ? (
                  <>
                    {"\n"}
                    <span className="text-slate-500">{"// target "}</span>
                    <span className="break-all text-slate-400">{target}</span>
                  </>
                ) : null}
                {"\n"}
                <span className="font-semibold text-sky-300">{name}</span>
                <span className="text-slate-400">(</span>
                {decoded.argument_words.length === 0 ? null : "\n"}
                {decoded.argument_words.map((w, i) => (
                  <span key={i}>
                    {"  "}
                    <span className="text-cyan-300">{types?.[i] ?? "word"}</span>
                    <span className="text-slate-500"> w{i} = </span>
                    <Literal word={w} type={types?.[i]} />
                    {i < decoded.argument_words.length - 1 ? <span className="text-slate-400">,</span> : null}
                    {"\n"}
                  </span>
                ))}
                <span className="text-slate-400">)</span>
              </code>
            </pre>
            {calldata ? (
              <details className="group rounded-lg border border-sky-400/10 bg-slate-950/50">
                <summary className="cursor-pointer select-none px-3 py-1.5 font-sans text-[12px] text-muted hover:text-ink">
                  Raw calldata · {(calldata.length - 2) / 2} bytes
                </summary>
                <div className="border-t border-sky-400/10 px-3 py-2 text-[11.5px] leading-relaxed">
                  <Hex calldata={calldata} />
                </div>
              </details>
            ) : null}
          </div>
        ) : (
          <p className="p-4 font-sans text-sm text-muted">Paste calldata to decode the selector and its arguments.</p>
        )}
      </section>
    </div>
  );
}
