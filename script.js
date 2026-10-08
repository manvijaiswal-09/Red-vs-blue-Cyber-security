// ---------- helpers ----------
const $ = s => document.querySelector(s);

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  Object.assign(n, props);
  kids.flat().forEach(k => n.append(k));
  return n;
}

// Seeded random generator: same seed -> same logs (repeatable demo)
const rng = seed => {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = a + 0x6D2B79F5 | 0;
    let t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
};

const fmt = ms => String(Math.floor(ms / 60000)).padStart(2, "0") + ":" + String(Math.floor(ms / 1000) % 60).padStart(2, "0");
const lc = v => String(v ?? "").toLowerCase();
const arr = x => Array.isArray(x) ? x : [x];

// default values for every log event
const DEF = {
  host: "WS-01", user: "-", src_ip: "-", dst_ip: "-", event_id: 0, category: "", image: "-",
  parent_image: "-", command_line: "-", target_image: "-", logon_type: 0, bytes_out: 0,
  scenario: null, malicious: false
};

// ---------- Red team: attack scenarios (synthetic logs only) ----------
const SYS = "C:\\Windows\\System32\\", PUB = "C:\\Users\\Public\\";

const SCENARIOS = [
  { id: "phish", name: "Phishing doc spawns shell", tech: "T1566", tactic: "Initial Access",
    gen: r => [{ dt: 0, event_id: 4688, category: "process", user: "priya", host: "WS-07",
      parent_image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", image: SYS + "cmd.exe", command_line: "cmd.exe /c whoami" }] },

  { id: "ps", name: "PowerShell encoded command", tech: "T1059.001", tactic: "Execution",
    gen: r => [{ dt: 0, event_id: 4688, category: "process", user: "john", host: "WS-04", parent_image: SYS + "cmd.exe",
      image: SYS + "WindowsPowerShell\\v1.0\\powershell.exe", command_line: "powershell.exe -nop -w hidden -enc JABhAD0AMQA=" }] },

  { id: "task", name: "Scheduled task persistence", tech: "T1053.005", tactic: "Persistence",
    gen: r => [{ dt: 0, event_id: 4688, category: "process", user: "john", host: "WS-04", parent_image: SYS + "cmd.exe",
      image: SYS + "schtasks.exe", command_line: "schtasks /create /tn Updater /tr " + PUB + "u.exe /sc minute /mo 5" }] },

  { id: "clear", name: "Event log cleared", tech: "T1070.001", tactic: "Defense Evasion",
    gen: r => [{ dt: 0, event_id: 1102, category: "log_cleared", user: "admin", host: "SRV-DC01",
      image: SYS + "wevtutil.exe", command_line: "wevtutil cl Security" }] },

  { id: "brute", name: "Password brute force", tech: "T1110", tactic: "Credential Access",
    gen: r => {
      const ip = "185.220.101." + (1 + Math.floor(r() * 200));
      return Array.from({ length: 15 }, (_, i) => ({ dt: i * 3000, event_id: 4625, category: "logon_failed",
        user: "admin", src_ip: ip, host: "SRV-DC01" }));
    } },

  { id: "lsass", name: "LSASS memory access", tech: "T1003.001", tactic: "Credential Access",
    gen: r => [{ dt: 0, event_id: 10, category: "process_access", user: "admin", host: "SRV-APP02",
      image: PUB + "procdump.exe", target_image: SYS + "lsass.exe", command_line: "procdump.exe -ma lsass.exe" }] },

  { id: "rdp", name: "RDP lateral movement", tech: "T1021.001", tactic: "Lateral Movement",
    gen: r => Array.from({ length: 5 }, (_, i) => ({ dt: i * 20000, event_id: 4624, category: "logon", logon_type: 10,
      user: "admin", src_ip: "10.0.0.23", host: "SRV-0" + (i + 1) })) },

  { id: "exfil", name: "Large data exfiltration", tech: "T1048", tactic: "Exfiltration",
    gen: r => Array.from({ length: 3 }, (_, i) => ({ dt: i * 45000, event_id: 5156, category: "network", user: "admin",
      host: "FS-01", src_ip: "10.0.0.15", dst_ip: "45.33.12.8", image: PUB + "sync.exe",
      bytes_out: 80e6 + Math.floor(r() * 40e6) })) }
];

const TACTICS = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Lateral Movement", "Exfiltration"];

// ---------- Benign noise (+ a few harmless events that can trigger loose rules) ----------
function noise(r, n) {
  const users = ["asha", "ravi", "meera", "john", "priya"], T = 1200000, out = [];
  const pick = a => a[Math.floor(r() * a.length)];

  for (let i = 0; i < n; i++) {
    const user = pick(users);
    const host = "WS-" + String(1 + Math.floor(r() * 12)).padStart(2, "0");
    const ts = Math.floor(r() * T), k = r();

    if (k < .4) out.push({ ts, host, user, event_id: 4624, category: "logon", logon_type: pick([2, 3]),
      src_ip: "10.0.0." + (10 + Math.floor(r() * 40)) });
    else if (k < .7) out.push({ ts, host, user, event_id: 4688, category: "process",
      image: "C:\\Program Files\\Google\\Chrome\\chrome.exe", parent_image: "C:\\Windows\\explorer.exe",
      command_line: "chrome.exe --profile-directory=Default" });
    else if (k < .85) out.push({ ts, host, user, event_id: 4688, category: "process",
      image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", parent_image: "C:\\Windows\\explorer.exe",
      command_line: "WINWORD.EXE report.docx" });
    else out.push({ ts, host, user, event_id: 5156, category: "network",
      image: "C:\\Program Files\\Google\\Chrome\\chrome.exe", src_ip: "10.0.0.20", dst_ip: "142.250.77.14",
      bytes_out: 5000 + Math.floor(r() * 2e6) });
  }

  // harmless events that loose rules will wrongly flag (false positives)
  const t = () => Math.floor(r() * T);
  out.push({ ts: t(), host: "FS-01", user: "svc_backup", event_id: 4688, category: "process",
    image: SYS + "schtasks.exe", parent_image: SYS + "cmd.exe",
    command_line: "schtasks /create /tn NightlyBackup /tr C:\\Backup\\run.bat /sc daily" });
  out.push({ ts: t(), host: "SRV-APP01", user: "sccm_svc", event_id: 4688, category: "process",
    image: SYS + "WindowsPowerShell\\v1.0\\powershell.exe", parent_image: "C:\\Windows\\CCM\\CcmExec.exe",
    command_line: "powershell.exe -EncodedCommand UwB0AGEAcgB0AA==" });
  out.push({ ts: t(), host: "SRV-DC01", user: "SYSTEM", event_id: 10, category: "process_access",
    image: "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", target_image: SYS + "lsass.exe",
    command_line: "MsMpEng.exe" });
  const b = t();
  for (let i = 0; i < 2; i++) out.push({ ts: b + i * 8000, host: "WS-03", user: "asha", event_id: 4625,
    category: "logon_failed", src_ip: "10.0.0.21" });

  return out.map(o => ({ ...DEF, ...o }));
}

// ---------- Blue team: rule engine ----------
function test(val, cond) {
  if (cond === null || typeof cond !== "object") return lc(val) === lc(cond);
  if (Array.isArray(cond)) return cond.some(c => lc(val) === lc(c));
  const v = lc(val);
  return Object.entries(cond).every(([op, arg]) => {
    switch (op) {
      case "contains":   return arr(arg).some(a => v.includes(lc(a)));
      case "startswith": return arr(arg).some(a => v.startsWith(lc(a)));
      case "endswith":   return arr(arg).some(a => v.endsWith(lc(a)));
      case "in":         return arr(arg).some(a => v === lc(a));
      case "not_in":     return !arr(arg).some(a => v === lc(a));
      case "ne":         return v !== lc(arg);
      case "gt":         return Number(val) > Number(arg);
      case "lt":         return Number(val) < Number(arg);
      default: throw new Error("Unknown operator: " + op);
    }
  });
}

function detect(events, rules) {
  const alerts = [];
  for (const rule of rules.filter(r => r.enabled !== false)) {
    if (!rule.match || typeof rule.match !== "object") {
      throw new Error((rule.id || "?") + ": 'match' is required");
    }

    // 1. which events match the rule conditions?
    const hits = [];
    events.forEach((e, i) => {
      if (Object.entries(rule.match).every(([f, c]) => test(e[f], c))) hits.push({ e, i });
    });

    // 2. simple rule: one alert per matching event
    const th = rule.threshold;
    if (!th) { hits.forEach(h => alerts.push({ ts: h.e.ts, rule, ev: [h.i] })); continue; }

    // 3. threshold rule: group events, then slide a time window over each group
    const groups = {};
    hits.forEach(h => (groups[h.e[th.group_by] ?? "*"] ??= []).push(h));
    const win = (th.window_s || 60) * 1000;

    for (const g of Object.values(groups)) {
      let start = 0, quietUntil = -1;
      for (let end = 0; end < g.length; end++) {
        while (g[end].e.ts - g[start].e.ts > win) start++;
        const slice = g.slice(start, end + 1);
        const n = th.distinct ? new Set(slice.map(x => x.e[th.distinct])).size : slice.length;
        if (n >= th.count && g[end].e.ts > quietUntil) {
          alerts.push({ ts: g[end].e.ts, rule, ev: slice.map(x => x.i) });
          quietUntil = g[end].e.ts + win;
        }
      }
    }
  }
  return alerts.sort((a, b) => a.ts - b.ts);
}

const DEFAULT_RULES = [
  { id: "R1", title: "Many failed logons from one source", technique: "T1110",
    match: { event_id: 4625 }, threshold: { count: 10, window_s: 60, group_by: "src_ip" } },
  { id: "R2", title: "PowerShell encoded command", technique: "T1059.001",
    match: { image: { endswith: "powershell.exe" }, command_line: { contains: "-enc" } } },
  { id: "R3", title: "Scheduled task created", technique: "T1053.005",
    match: { command_line: { contains: "schtasks /create" } } },
  { id: "R4", title: "Office app spawns shell", technique: "T1566",
    match: { parent_image: { endswith: ["winword.exe", "excel.exe", "outlook.exe"] }, image: { endswith: ["cmd.exe", "powershell.exe"] } } },
  { id: "R5", title: "Process accesses LSASS", technique: "T1003.001",
    match: { event_id: 10, target_image: { endswith: "lsass.exe" } } },
  { id: "R6", title: "Security log cleared", technique: "T1070.001",
    match: { event_id: 1102 } }
];

// ---------- App state & flow ----------
let events = [], selected = [], lastReport = null;

function simulate() {
  const r = rng(+$("#seed").value || 1);
  selected = SCENARIOS.filter(s => $("#sc_" + s.id).checked);
  const ev = [];

  selected.forEach(s => {
    const start = Math.floor(r() * 900000);
    s.gen(r).forEach(({ dt, ...f }) => ev.push({ ...DEF, ...f, ts: start + dt, scenario: s.id, malicious: true }));
  });

  ev.push(...noise(r, +$("#noise").value));
  events = ev.sort((a, b) => a.ts - b.ts);
  analyze();
}

function analyze() {
  let rules, alerts;
  try {
    rules = JSON.parse($("#rules").value);
    if (!Array.isArray(rules)) throw new Error("Rules must be a JSON array");
    alerts = detect(events, rules);
  } catch (e) {
    return showErr("Rule error: " + e.message);
  }
  showErr("");
  render(alerts);
}

function showErr(m) {
  const e = $("#err");
  e.textContent = m;
  e.style.display = m ? "block" : "none";
}

function render(alerts) {
  // per-scenario result
  const rows = selected.map(s => {
    const hit = alerts.filter(a => a.ev.some(i => events[i].scenario === s.id));
    const first = Math.min(...events.filter(e => e.scenario === s.id).map(e => e.ts));
    return {
      s, detected: hit.length > 0, rule: hit[0]?.rule,
      mttd: hit.length ? Math.max(0, (hit[0].ts - first) / 1000) : null
    };
  });

  // false positive = alert where none of the evidence events is malicious
  const fpAlerts = alerts.filter(a => a.ev.every(i => !events[i].malicious));
  const det = rows.filter(x => x.detected).length;
  const mttds = rows.filter(x => x.mttd !== null).map(x => x.mttd);
  const avg = mttds.length ? (mttds.reduce((a, b) => a + b, 0) / mttds.length).toFixed(1) + "s" : "-";
  const rate = rows.length ? Math.round(det / rows.length * 100) : 0;

  // stat cards
  const stats = $("#stats"); stats.replaceChildren();
  [["Detection rate", rate + "%"], ["Detected", det + " / " + rows.length], ["Missed", rows.length - det],
   ["False positives", fpAlerts.length], ["Avg time to detect", avg], ["Events analysed", events.length]]
    .forEach(([k, v]) => stats.append(el("div", { className: "stat" },
      el("span", { className: "mut", textContent: k }), el("b", { textContent: v }))));

  // results table
  const t = $("#resTable");
  t.replaceChildren(el("tr", {}, ["Attack", "Technique", "Result", "Caught by", "Time to detect"].map(h => el("th", { textContent: h }))));
  rows.forEach(x => t.append(el("tr", {},
    el("td", { textContent: x.s.name }),
    el("td", { textContent: x.s.tech }),
    el("td", {}, el("span", { className: "tag " + (x.detected ? "ok" : "miss"), textContent: x.detected ? "DETECTED" : "MISSED" })),
    el("td", { textContent: x.rule ? x.rule.id + ": " + x.rule.title : "No rule fired. Write one!" }),
    el("td", { textContent: x.mttd !== null ? x.mttd.toFixed(0) + "s" : "-" }))));

  // MITRE matrix
  const m = $("#matrix"); m.replaceChildren();
  TACTICS.forEach(tac => {
    const col = el("div", { className: "col" }, el("h3", { textContent: tac }));
    SCENARIOS.filter(s => s.tactic === tac).forEach(s => {
      const row = rows.find(x => x.s.id === s.id);
      col.append(el("div", { className: "cell " + (row ? (row.detected ? "ok" : "miss") : ""),
        textContent: s.tech + " · " + s.name }));
    });
    m.append(col);
  });

  // event log (textContent only, so log data can never inject HTML)
  const byEv = {};
  alerts.forEach(a => a.ev.forEach(i => (byEv[i] ??= new Set()).add(a.rule.id)));
  const only = $("#onlyInt").checked;
  const lt = $("#logTable");
  lt.replaceChildren(el("tr", {}, ["Time", "Host", "User", "Event", "Detail", "Alerts"].map(h => el("th", { textContent: h }))));

  let shown = 0;
  events.forEach((e, i) => {
    if (only && !e.malicious && !byEv[i]) return;
    if (shown++ > 250) return;
     const detail = e.command_line !== "-" ? e.command_line
  : e.bytes_out ? e.src_ip + " → " + e.dst_ip + " (" + (e.bytes_out / 1e6).toFixed(0) + " MB)"
  : e.src_ip + " logon type " + e.logon_type;
    lt.append(el("tr", { className: (e.malicious ? "mal " : "") + (byEv[i] ? "alerted" : "") },
      el("td", { textContent: fmt(e.ts) }),
      el("td", { textContent: e.host }),
      el("td", { textContent: e.user }),
      el("td", { textContent: e.category + " (" + e.event_id + ")" }),
      el("td", { textContent: detail }),
      el("td", {}, byEv[i]
        ? el("span", { className: "tag " + (e.malicious ? "ok" : "warn"),
            textContent: [...byEv[i]].join(", ") + (e.malicious ? "" : " FP") })
        : "")));
  });

  lastReport = {
    detection_rate: rate, detected: det, tested: rows.length, false_positives: fpAlerts.length, avg_mttd: avg,
    scenarios: rows.map(x => ({ name: x.s.name, technique: x.s.tech, detected: x.detected, rule: x.rule?.id || null }))
  };
}

// ---------- UI wiring ----------
SCENARIOS.forEach(s => $("#scList").append(el("label", { className: "row" },
  el("input", { type: "checkbox", id: "sc_" + s.id, checked: true }),
  el("span", {}, s.name, el("br"), el("span", { className: "mut", textContent: s.tech + " · " + s.tactic })))));

$("#rules").value = JSON.stringify(DEFAULT_RULES, null, 2);
$("#noise").oninput = e => $("#noiseVal").textContent = e.target.value;
$("#runBtn").onclick = simulate;
$("#dice").onclick = () => { $("#seed").value = Math.floor(Math.random() * 99999); simulate(); };
$("#applyBtn").onclick = () => events.length ? analyze() : simulate();
$("#resetBtn").onclick = () => {
  $("#rules").value = JSON.stringify(DEFAULT_RULES, null, 2);
  events.length ? analyze() : simulate();
};
$("#onlyInt").onchange = () => events.length && analyze();
$("#dl").onclick = () => {
  if (!lastReport) return;
  el("a", {
    href: URL.createObjectURL(new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" })),
    download: "detection-report.json"
  }).click();
};

simulate();