// All model output and on-chain text is untrusted, so the DOM is only ever built with textContent.
const $ = (id) => document.getElementById(id);
const h = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const POISON = "0xbad0000000000000000000000000000000c0ffee";
const EXAMPLES = [
  ["Check a token", "Is 0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed on Base safe to hold? Check honeypot risk, mint rights, holder concentration and liquidity."],
  ["Who holds it", "Who are the top 5 holders of 0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed on Base and how much do they control together?"],
  ["Poisoned token", `Is ${POISON} on Base safe to hold?`],
];
let cursor = 0, timer = null, runId = null, finished = false;

function showError(msg) {
  $("err").textContent = msg;
  $("err").hidden = !msg;
}

async function start(url, body) {
  showError("");
  $("go").disabled = $("attack").disabled = true;
  try {
    const res = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "That didn't work. Try again.");
    history.pushState({}, "", "/r/" + data.id);
    open(data.id);
  } catch (e) {
    showError(e.message);
  } finally {
    $("go").disabled = $("attack").disabled = false;
  }
}

function open(id) {
  runId = id; cursor = 0; finished = false;
  $("hero").hidden = true; $("how").hidden = true; $("run").hidden = false;
  $("timeline").replaceChildren(); $("verdict").replaceChildren();
  $("run-title").textContent = "";
  poll();
}

async function poll() {
  clearTimeout(timer);
  let run;
  try {
    const res = await fetch(`/api/runs/${encodeURIComponent(runId)}?after=${cursor}`);
    if (res.status === 404) { $("run-title").textContent = "No receipt with that link."; $("state").hidden = true; return; }
    run = await res.json();
  } catch { timer = setTimeout(poll, 2500); return; }
  $("run-title").textContent = run.kind === "attack" ? "Trying to break out of the sandbox" : run.question;
  const state = $("state");
  state.textContent = run.status === "running" ? "running" : run.status;
  state.className = "state " + run.status;
  for (const ev of run.events) { render(ev, run); cursor = ev.seq; }
  if (run.status === "failed" && !finished) {
    finished = true;
    const box = h("div", "tl"); box.append(h("h4", "", "This run stopped")); box.append(h("p", "", run.error || "Unknown error"));
    $("timeline").append(box);
  }
  if (run.status === "running") timer = setTimeout(poll, 1000);
}

function note(text) { const n = h("div", "tl note"); n.append(h("p", "", text)); n.firstChild.style.margin = 0; $("timeline").append(n); }

function proofTags(d) {
  const row = h("div", "proof");
  const add = (t, cls) => row.append(h("span", "tag " + (cls || ""), t));
  add(`${d.runtime}`);
  add(`container ${d.container || "n/a"}`);
  add(`exit ${d.exit_code}`);
  add(`${(d.duration_ms / 1000).toFixed(1)}s`);
  add(`${d.limits.memory_mb} MB · ${d.limits.cpus} CPU · ${d.limits.pids} procs`);
  add(`code ${d.code_sha256.slice(0, 12)}`);
  add(`output ${d.stdout_sha256.slice(0, 12)}`);
  if (d.killed) add(`killed: ${d.killed}`, "bad");
  add(d.destroyed ? "destroyed, confirmed" : "NOT destroyed", d.destroyed ? "ok" : "bad");
  const hosts = [...new Set((d.egress || []).filter(e => e.allowed).map(e => e.host))];
  const denied = (d.egress || []).filter(e => !e.allowed);
  if (hosts.length) add(`reached: ${hosts.join(", ")}`);
  for (const e of denied) add(`refused: ${e.host}:${e.port}`, "ok");
  return row;
}

function execution(d) {
  const box = h("div", "tl");
  box.append(h("h4", "", d.attempt > 1 ? `${d.title} (attempt ${d.attempt})` : d.title));
  const code = h("details"); code.append(h("summary", "", "The code it ran")); code.append(h("pre", "term", d.code));
  box.append(code);
  if (d.stdout) box.append(h("pre", "term", d.stdout.length > 6000 ? d.stdout.slice(0, 6000) + "\n...[shortened here, hash covers the full output]" : d.stdout));
  if (d.stderr) box.append(h("pre", "term err-out", d.stderr.slice(-1500)));
  box.append(proofTags(d));
  $("timeline").append(box);
}

function answer(d) {
  const r = h("div", "receipt");
  const risk = d.risk && d.risk !== "not_applicable" ? d.risk : null;
  if (risk) r.append(h("span", "risk " + risk, `RISK: ${risk.toUpperCase()}`));
  r.append(h("h3", "", d.headline));
  r.append(h("p", "", d.summary));
  if (d.unbacked_numbers && d.unbacked_numbers.length) {
    r.append(h("p", "warn", `Not found in the output, so don't rely on: ${d.unbacked_numbers.join(", ")}`));
  }
  r.append(h("hr", "rule"));
  for (const c of d.claims) {
    const row = h("div", "claim" + (c.verified ? "" : " no"));
    row.append(h("span", "tick", c.verified ? "✓" : "✗"));
    const body = h("div");
    body.append(h("b", "", c.text));
    body.append(h("code", "", c.verified ? `"${c.value}" found in step ${c.step} output` : `"${c.value}" NOT in the output, don't rely on this`));
    row.append(body);
    r.append(row);
  }
  r.append(h("hr", "rule"));
  const line = (a, b) => { const t = h("div", "totals"); t.append(h("span", "", a)); t.append(h("span", "", b)); r.append(t); };
  line("Claim values found in the output", `${d.verified} of ${d.total}`);
  line("Sandboxes used", String(d.sandboxes));
  line("Sandboxes destroyed", d.all_destroyed ? "all, confirmed" : "NOT all");
  $("verdict").replaceChildren(r);
}

let probeBox = null;
function probe(d) {
  if (!probeBox) {
    probeBox = h("div", "tl");
    probeBox.append(h("h4", "", "Attempts"));
    $("timeline").prepend(probeBox);
  }
  const row = h("div", "probe");
  row.append(h("span", "st " + (d.escaped ? "escaped" : "blocked"), d.escaped ? "ESCAPED" : "BLOCKED"));
  const body = h("div"); body.append(h("b", "", d.title)); body.append(h("small", "", d.detail));
  row.append(body);
  probeBox.append(row);
}

function attackSummary(d) {
  const r = h("div", "receipt");
  r.append(h("div", "label", "Blast radius"));
  r.append(h("div", "blast" + (d.escaped ? " bad" : ""), String(d.escaped)));
  r.append(h("p", "", d.escaped ? `${d.escaped} of ${d.attempts} attempts got out. Treat this sandbox as unsafe.` : `None of the ${d.attempts} attempts got out of the sandbox.`));
  r.append(h("hr", "rule"));
  const line = (a, b) => { const t = h("div", "totals"); t.append(h("span", "", a)); t.append(h("span", "", b)); r.append(t); };
  line("Runtime", d.runtime);
  line("Host scan for its own secrets", d.secret_scan_clean ? `clean (${d.secrets_checked} checked)` : "LEAK FOUND");
  line("Connections the proxy refused", String(d.denied_by_proxy.length));
  for (const e of d.denied_by_proxy) line(`  ${e.host}:${e.port}`, e.reason);
  line("Approved route still works", d.control && d.control.control ? "yes" : "no");
  if (d.control) line("", d.control.detail);
  line("Sandboxes destroyed", d.all_destroyed ? "all, confirmed" : "NOT all");
  $("verdict").replaceChildren(r);
}

function render(ev) {
  const d = ev.data;
  switch (ev.type) {
    case "plan": note(`Plan: ${d.steps.map(s => s.title).join(" → ")}`); break;
    case "execution": execution(d); break;
    case "retry": note(`That attempt failed, so the error goes back to the model: ${d.problem}`); break;
    case "recheck": note(`The checker rejected ${d.unverified.length} value(s) that weren't in the output, so the model gets one chance to correct them.`); break;
    case "answer": answer(d); break;
    case "attack_stage": note(`Attempt: ${d.title}`); break;
    case "probe": probe(d); break;
    case "attack_summary": attackSummary(d); break;
  }
}

async function loadStatus() {
  try {
    const s = await (await fetch("/api/status")).json();
    const m = $("meta"); m.replaceChildren();
    const add = (k, v) => { const sp = h("span", "", k + " "); sp.append(h("b", "", v)); m.append(sp); };
    add("model", s.model);
    add("sandbox", s.runtime);
    add("sandboxes run", String(s.sandboxes));
    add("escapes", `${s.escaped} of ${s.attacks}`);
    if (!s.inference) { $("go").disabled = true; showError("Questions are offline right now, but you can still try to break the sandbox."); }
  } catch {}
}

for (const [label, text] of EXAMPLES) {
  const c = h("button", "chip", label); c.type = "button";
  c.onclick = () => { $("q").value = text; $("q").focus(); };
  $("chips").append(c);
}
$("ask").onsubmit = (e) => { e.preventDefault(); start("/api/investigate", {question: $("q").value.trim() || $("q").placeholder}); };
$("attack").onclick = () => start("/api/attack", {});
$("copy").onclick = async () => { await navigator.clipboard.writeText(location.href); $("copy").textContent = "Copied"; setTimeout(() => $("copy").textContent = "Copy link", 1500); };
$("q").onkeydown = (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) $("ask").requestSubmit(); };
window.onpopstate = () => location.reload();
const m = location.pathname.match(/^\/r\/([\w-]+)/);
if (m) open(m[1]);
loadStatus();
