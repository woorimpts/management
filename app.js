"use strict";
/*  부서 업무 달력
 *  - 업무·휴가·체크 기록은 Firestore 에 저장되며, 모두 사이트 비밀번호로 암호화(AES-GCM)됩니다.
 *  - Firestore 컬렉션
 *      items  : { kind: task|vacation|note, months: ["2026-11"], iv, ct, at }
 *      checks : { months, item, iv, ct, at }   (문서 ID = 업무 ID)
 */

const FIREBASE_VER = "10.12.2";
const XLSX_URL = "https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js";
const WEEK = ["일", "월", "화", "수", "목", "금", "토"];
const VAC_TYPES = ["연차", "오전반차", "오후반차", "반반차", "병가", "경조휴가", "출장", "교육", "기타"];

// ───────── 공통 유틸 ─────────
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pad = (n) => String(n).padStart(2, "0");
const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const TODAY = iso(new Date());
const md = (s) => { const [, m, d] = s.split("-"); return `${+m}/${+d}`; };
const dow = (s) => new Date(s + "T00:00").getDay();
const mdw = (s) => `${md(s)}(${WEEK[dow(s)]})`;
const period = (a, b) => (!a ? "" : !b || a === b ? mdw(a) : `${mdw(a)} ~ ${mdw(b)}`);
const stripNum = (t) => t.replace(/^\d+\s*\.\s*/, "");
const isISO = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s || "");

function store(key, val) {
  try {
    if (val === undefined) return localStorage.getItem(key);
    if (val === null) localStorage.removeItem(key); else localStorage.setItem(key, val);
  } catch (e) { return null; }
}
function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src; s.onload = res; s.onerror = () => rej(new Error("load fail " + src));
    document.head.appendChild(s);
  });
}
function monthsOf(start, end) {
  if (!isISO(start)) return [];
  const out = [];
  let [y, m] = start.split("-").map(Number);
  const last = (isISO(end) && end > start ? end : start).slice(0, 7);
  for (let i = 0; i < 13; i++) {
    const k = `${y}-${pad(m)}`;
    out.push(k);
    if (k >= last) break;
    m++; if (m > 12) { m = 1; y++; }
  }
  return out;
}
let toastTimer;
function toast(msg) {
  const el = $("#toast");
  el.textContent = msg; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

// ───────── 암호화 ─────────
const TE = new TextEncoder(), TD = new TextDecoder();
let KEY = null;
function b64e(u8) { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
function b64d(s) { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
async function deriveKey(pw) {
  const L = window.LOCK;
  const base = await crypto.subtle.importKey("raw", TE.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64d(L.salt), iterations: L.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, KEY, TE.encode(JSON.stringify(obj)));
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}
async function unseal(iv, ct, key = KEY) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(iv) }, key, b64d(ct));
  return TD.decode(pt);
}

// ───────── 잠금 화면 ─────────
(function lockScreen() {
  const lock = $("#lock"), form = $("#lockForm"), input = $("#lockPw"), msg = $("#lockMsg");
  if (!window.crypto || !crypto.subtle) { lock.classList.add("ready"); msg.textContent = "이 브라우저는 지원되지 않습니다. 크롬·엣지 최신 버전으로 접속해 주세요."; return; }

  async function tryOpen(pw, remember) {
    try {
      const key = await deriveKey(pw);
      await unseal(window.LOCK.iv, window.LOCK.ct, key);
      KEY = key;
      if (remember) store("sitePw", pw);
      lock.hidden = true;
      document.body.classList.remove("locked");
      boot();
      return true;
    } catch (e) { return false; }
  }
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "확인 중…";
    const ok = await tryOpen(input.value, $("#lockRemember").checked);
    if (!ok) { msg.textContent = "비밀번호가 맞지 않습니다."; input.select(); }
  });
  const saved = store("sitePw");
  (saved ? tryOpen(saved, true) : Promise.resolve(false)).then((ok) => {
    if (!ok) { store("sitePw", null); lock.classList.add("ready"); input.focus(); }
  });
})();

// ───────── 상태 ─────────
const S = {
  month: TODAY.slice(0, 7),
  tasks: [], vacs: [], notes: [],
  checks: {},
  loaded: false,
  dept: store("dept") || "all",
  hideDone: store("hideDone") === "1",
  showVac: store("showVac") !== "0",
  view: store("view") || "calendar",
  sel: TODAY,
};
let db = null;
const userName = () => $("#userName").value.trim();

// ───────── Firestore ─────────
const cache = new Map();
async function readDocs(docs) {
  const out = [];
  for (const doc of docs) {
    const d = doc.data();
    if (!d.iv || !d.ct) continue;
    const k = doc.id + ":" + d.iv;
    let v = cache.get(k);
    if (v === undefined) {
      try { v = JSON.parse(await unseal(d.iv, d.ct)); } catch (e) { v = null; } // 다른 비밀번호/손상 데이터는 무시
      cache.set(k, v);
    }
    if (v) out.push({ ...v, id: doc.id, kind: d.kind, months: d.months || [] });
  }
  return out;
}

let unsubs = [];
function subscribe(month) {
  unsubs.forEach((u) => u()); unsubs = [];
  S.loaded = false; S.tasks = []; S.vacs = []; S.notes = []; S.checks = {};
  setSync("", "불러오는 중…");
  let gotItems = false, gotChecks = false;
  const done = () => { if (gotItems && gotChecks) { S.loaded = true; setSync("live", "실시간 공유 중"); } render(); };
  const onErr = (e) => { console.error(e); setSync("err", "연결 오류 — 새로고침 해주세요"); };

  unsubs.push(db.collection("items").where("months", "array-contains", month).onSnapshot(async (snap) => {
    const list = await readDocs(snap.docs);
    if (S.month !== month) return;
    S.tasks = list.filter((x) => x.kind === "task").sort(taskOrder);
    S.vacs = list.filter((x) => x.kind === "vacation").sort((a, b) => (a.start || "").localeCompare(b.start || "") || (a.name || "").localeCompare(b.name || ""));
    S.notes = list.filter((x) => x.kind === "note").sort((a, b) => (a.ord ?? 0) - (b.ord ?? 0));
    gotItems = true; done();
  }, onErr));

  unsubs.push(db.collection("checks").where("months", "array-contains", month).onSnapshot(async (snap) => {
    const list = await readDocs(snap.docs);
    if (S.month !== month) return;
    const map = {};
    list.forEach((c) => { map[c.item || c.id] = c; });
    S.checks = map;
    gotChecks = true; done();
  }, onErr));
}
function taskOrder(a, b) {
  return (a.batch || "~").localeCompare(b.batch || "~") || (a.ord ?? 1e9) - (b.ord ?? 1e9) ||
    (a.start || "9").localeCompare(b.start || "9") || (a.title || "").localeCompare(b.title || "");
}

const serverTime = () => firebase.firestore.FieldValue.serverTimestamp();
async function saveItem(kind, data, id) {
  const { id: _i, kind: _k, months: _m, ...plain } = data;
  const months = data.start ? monthsOf(data.start, data.end) : (data.months && data.months.length ? data.months : [S.month]);
  const { iv, ct } = await seal(plain);
  const payload = { kind, months, iv, ct, at: serverTime() };
  if (id) await db.collection("items").doc(id).set(payload);
  else await db.collection("items").add(payload);
}
async function deleteItem(id) { await db.collection("items").doc(id).delete(); }
async function setCheck(entry, done) {
  const { iv, ct } = await seal({ done, by: userName(), at: Date.now() });
  await db.collection("checks").doc(entry.id).set({ months: entry.task.months, item: entry.id, iv, ct, at: serverTime() });
}

function setSync(cls, text) {
  const el = $("#syncStatus");
  el.className = "sync " + cls;
  $("b", el).textContent = text;
}

// ───────── 부서 색상 ─────────
let DEPTS = [];
function computeDepts() {
  const ds = [];
  S.tasks.forEach((t) => { if (t.dept && !ds.includes(t.dept)) ds.push(t.dept); });
  S.vacs.forEach((v) => { if (v.dept && !ds.includes(v.dept)) ds.push(v.dept); });
  DEPTS = ds;
  if (S.dept !== "all" && !ds.includes(S.dept) && S.loaded) S.dept = "all";
}
const color = (dept) => (DEPTS.includes(dept) ? `var(--d${DEPTS.indexOf(dept) % 8})` : "var(--d-none)");
const deptOk = (d) => S.dept === "all" || S.dept === d;
const knownDepts = () => {
  const saved = (store("knownDepts") || "").split("|").filter(Boolean);
  return [...new Set([...DEPTS, ...saved])];
};
function rememberDept(d) {
  if (!d) return;
  const list = [...new Set([d, ...(store("knownDepts") || "").split("|").filter(Boolean)])].slice(0, 30);
  store("knownDepts", list.join("|"));
}

// ───────── 데이터 가공 ─────────
const isDone = (id) => !!(S.checks[id] && S.checks[id].done);
function entries() {
  const out = [];
  S.tasks.forEach((t) => {
    if (t.start) out.push({ id: t.id, task: t, start: t.start, end: t.end || t.start, title: t.title });
    (t.subs || []).forEach((s) => { if (s.own) out.push({ id: s.id, task: t, sub: s, start: s.start, end: s.end || s.start, title: s.title }); });
  });
  return out;
}
const isLate = (e) => !isDone(e.id) && e.end && e.end < TODAY;
function checkables() {
  const out = [];
  S.tasks.forEach((t) => {
    out.push({ id: t.id, dept: t.dept, end: t.end || t.start });
    (t.subs || []).forEach((s) => { if (s.own) out.push({ id: s.id, dept: t.dept, end: s.end || s.start }); });
  });
  return out;
}
function dayEntries(date) {
  return entries().filter((e) => e.start <= date && date <= e.end && deptOk(e.task.dept) && !(S.hideDone && isDone(e.id)));
}
function dayVacs(date) {
  if (!S.showVac) return [];
  const wd = dow(date);
  return S.vacs.filter((v) => v.start <= date && date <= (v.end || v.start) && (wd !== 0 && wd !== 6 || v.start === date) && (S.dept === "all" || !v.dept || v.dept === S.dept));
}

// ───────── 렌더링 ─────────
function render() {
  computeDepts();
  const [y, m] = S.month.split("-").map(Number);
  $("#monthLabel").textContent = `${y}년 ${m}월`;
  $("#hideDone").checked = S.hideDone;
  $("#showVac").checked = S.showVac;
  $$(".seg button").forEach((b) => b.classList.toggle("on", b.dataset.view === S.view));
  $("#calendarView").hidden = S.view !== "calendar";
  $("#listView").hidden = S.view !== "list";
  renderSummary();
  renderFilters();
  if (S.view === "calendar") { renderCalendar(); renderPanel(); } else renderList();
  renderExtra();
}

function renderSummary() {
  const items = checkables();
  const groups = [{ key: "all", name: "전체", c: "var(--text)" }].concat(DEPTS.filter((d) => items.some((i) => i.dept === d)).map((d) => ({ key: d, name: d, c: color(d) })));
  let html = groups.map((g) => {
    const list = g.key === "all" ? items : items.filter((i) => i.dept === g.key);
    const done = list.filter((i) => isDone(i.id)).length;
    const late = list.filter((i) => !isDone(i.id) && i.end && i.end < TODAY).length;
    const pct = list.length ? Math.round((done / list.length) * 100) : 0;
    return `<button class="stat ${S.dept === g.key ? "on" : ""}" data-dept="${esc(g.key)}" style="--c:${g.c}">
      <div class="name"><i></i>${esc(g.name)}</div>
      <div class="num">${pct}%<small>${done}/${list.length}</small></div>
      <div class="bar"><span style="width:${pct}%"></span></div>
      <div class="late">${late ? `기한 지남 ${late}건` : ""}</div></button>`;
  }).join("");
  const vacDays = new Set();
  S.vacs.forEach((v) => { if (S.dept === "all" || v.dept === S.dept) vacDays.add(v.name); });
  html += `<div class="stat vac-stat"><div class="name">🌴 이번 달 휴가</div><div class="num">${vacDays.size}<small>명</small></div>
    <div class="late muted">${S.vacs.filter((v) => v.start <= TODAY && TODAY <= (v.end || v.start)).length ? `오늘 휴가 ${S.vacs.filter((v) => v.start <= TODAY && TODAY <= (v.end || v.start)).length}명` : ""}</div></div>`;
  $("#summary").innerHTML = html;
}

function renderFilters() {
  $("#deptFilters").innerHTML =
    `<button class="chip ${S.dept === "all" ? "on" : ""}" data-dept="all">전체</button>` +
    DEPTS.map((d) => `<button class="chip ${S.dept === d ? "on" : ""}" data-dept="${esc(d)}" style="--c:${color(d)}"><i></i>${esc(d)}</button>`).join("");
}

function vacLabel(v) { return `${v.name}${v.type && v.type !== "연차" ? " " + v.type : ""}`; }

function renderCalendar() {
  $("#calHead").innerHTML = WEEK.map((w) => `<div>${w}</div>`).join("");
  const [y, m] = S.month.split("-").map(Number);
  const first = new Date(y, m - 1, 1);
  const start = new Date(y, m - 1, 1 - first.getDay());
  const last = new Date(y, m, 0);
  const cells = Math.ceil((first.getDay() + last.getDate()) / 7) * 7;
  let html = "";
  for (let i = 0; i < cells; i++) {
    const d = new Date(start); d.setDate(start.getDate() + i);
    const ds = iso(d);
    const out = d.getMonth() !== m - 1;
    const cls = ["cell", out && "out", ds === TODAY && "today", ds === S.sel && "sel", d.getDay() === 0 && "sun", d.getDay() === 6 && "sat"].filter(Boolean).join(" ");
    if (out) { html += `<div class="${cls}"><div class="dhead"><span class="dnum">${d.getDate()}</span></div></div>`; continue; }
    const list = dayEntries(ds);
    const vacs = dayVacs(ds);
    const doneN = list.filter((e) => isDone(e.id)).length;
    const lateN = list.filter(isLate).length;
    const countCls = lateN ? "late" : list.length && doneN === list.length ? "all" : "";
    const count = list.length ? `<span class="dcount ${countCls}">${doneN}/${list.length}</span>` : "";
    const vacHtml = vacs.length ? `<div class="vac-line" title="${esc(vacs.map(vacLabel).join(", "))}">🌴 ${esc(vacs.slice(0, 3).map(vacLabel).join(", "))}${vacs.length > 3 ? ` 외 ${vacs.length - 3}` : ""}</div>` : "";
    const MAX = vacs.length ? 3 : 4;
    const chips = list.slice(0, MAX).map((e) => {
      const done = isDone(e.id);
      return `<label class="task-chip ${done ? "done" : ""} ${isLate(e) ? "late" : ""}" style="--c:${color(e.task.dept)}" title="${esc(e.task.dept + " · " + (e.sub ? stripNum(e.task.title) + " › " : "") + e.title)}">
        <input type="checkbox" data-check="${esc(e.id)}" ${done ? "checked" : ""}><span>${esc(stripNum(e.title))}</span></label>`;
    }).join("");
    const more = list.length > MAX ? `<div class="more">+${list.length - MAX}건 더보기</div>` : "";
    const dots = `<div class="dots">${vacs.length ? '<i class="vac"></i>' : ""}${list.slice(0, 7).map((e) => `<i style="--c:${color(e.task.dept)}" class="${isDone(e.id) ? "done" : ""}"></i>`).join("")}</div>`;
    html += `<div class="${cls}" data-date="${ds}"><div class="dhead"><span class="dnum">${d.getDate()}</span>${count}</div>${vacHtml}${chips}${more}${dots}</div>`;
  }
  $("#calGrid").innerHTML = html;
}

function checkInfo(id) {
  const c = S.checks[id];
  if (!c || !c.done) return "";
  const t = new Date(c.at);
  return `<span class="by">✓ ${esc(c.by || "?")} · ${t.getMonth() + 1}/${t.getDate()} ${pad(t.getHours())}:${pad(t.getMinutes())}</span>`;
}

function taskCard(t) {
  const done = isDone(t.id);
  const late = !done && t.start && (t.end || t.start) < TODAY;
  const meta = [
    `<span class="dept">${esc(t.dept || "부서 미지정")}</span>`,
    t.start ? `<span>📅 ${period(t.start, t.end)}</span>` : t.dateText ? `<span>📅 ${esc(t.dateText)}</span>` : "",
    t.owner ? `<span>👤 ${esc(t.owner)}</span>` : "",
    t.due ? `<span>기한 ${mdw(t.due)}</span>` : t.dueText ? `<span>${esc(t.dueText)}</span>` : "",
    t.memo ? `<span>비고: ${esc(t.memo)}</span>` : "",
    late ? `<span class="late">기한 지남</span>` : "",
    checkInfo(t.id),
  ].join("");
  const subs = (t.subs || []).length ? `<ul class="subs">${t.subs.map((s) => {
    if (!s.own) return `<li><span class="t">${esc(s.title)}${s.dateText ? ` (${esc(s.dateText)})` : ""}</span></li>`;
    const sd = isDone(s.id);
    return `<li class="chk ${sd ? "done" : ""}"><input type="checkbox" data-check="${esc(s.id)}" ${sd ? "checked" : ""}>
      <span><span class="t">${esc(s.title)}</span> <span class="sd">${period(s.start, s.end)}</span> ${checkInfo(s.id)}</span></li>`;
  }).join("")}</ul>` : "";
  const added = t.src === "manual" && t.by ? `<span class="added">${esc(t.by)} 추가</span>` : "";
  return `<div class="task ${done ? "done" : ""}" style="--c:${color(t.dept)}">
    <button class="edit-btn" data-edit-task="${esc(t.id)}" title="수정/삭제" aria-label="수정">✎</button>
    <label class="task-row"><input type="checkbox" data-check="${esc(t.id)}" ${done ? "checked" : ""}>
      <div><div class="task-title">${esc(t.title)}</div><div class="meta">${meta}${added}</div></div></label>${subs}</div>`;
}

function subCard(e) {
  const s = e.sub, t = e.task, done = isDone(s.id);
  return `<div class="task ${done ? "done" : ""}" style="--c:${color(t.dept)}">
    <div class="parent-ref">${esc(t.title)} ›</div>
    <label class="task-row"><input type="checkbox" data-check="${esc(s.id)}" ${done ? "checked" : ""}>
      <div><div class="task-title">${esc(s.title)}</div>
      <div class="meta"><span class="dept">${esc(t.dept)}</span><span>📅 ${period(s.start, s.end)}</span>${isLate(e) ? '<span class="late">기한 지남</span>' : ""}${checkInfo(s.id)}</div></div></label></div>`;
}

function vacCard(v) {
  return `<div class="vac-card">
    <div><b>🌴 ${esc(v.name)}</b> <span class="vac-type">${esc(v.type || "휴가")}</span>
    <div class="meta">${v.dept ? `<span>${esc(v.dept)}</span>` : ""}<span>📅 ${period(v.start, v.end)}</span>${v.memo ? `<span>${esc(v.memo)}</span>` : ""}</div></div>
    <button class="edit-btn" data-edit-vac="${esc(v.id)}" title="수정/삭제" aria-label="수정">✎</button></div>`;
}

function renderPanel() {
  const d = S.sel && S.sel.startsWith(S.month) ? S.sel : S.month + "-01";
  const list = dayEntries(d);
  const vacs = dayVacs(d);
  const doneN = list.filter((e) => isDone(e.id)).length;
  const [, m, day] = d.split("-");
  $("#dayPanel").innerHTML = `<div class="panel-head">
      <div><h2>${+m}월 ${+day}일 (${WEEK[dow(d)]})${d === TODAY ? " · 오늘" : ""}</h2>
      <p>${list.length ? `업무 ${list.length}건 · 완료 ${doneN}건` : "업무 없음"}${vacs.length ? ` · 휴가 ${vacs.length}명` : ""}</p></div>
      <div class="panel-actions"><button class="small-btn" data-add-task="${d}">+ 업무</button><button class="small-btn vac" data-add-vac="${d}">+ 휴가</button></div></div>
    <div class="panel-body">
      ${vacs.length ? `<div class="sec-title">휴가</div>${vacs.map(vacCard).join("")}<div class="sec-title">업무</div>` : ""}
      ${!S.loaded ? '<div class="empty">불러오는 중…</div>' : list.length ? list.map((e) => (e.sub ? subCard(e) : taskCard(e.task))).join("") : '<div class="empty">이 날 마감인 업무가 없습니다.<br>위의 <b>+ 업무</b>로 추가할 수 있습니다.</div>'}
    </div>`;
}

function renderList() {
  const ds = DEPTS.filter((d) => deptOk(d) && S.tasks.some((t) => t.dept === d));
  if (S.tasks.some((t) => !t.dept) && S.dept === "all") ds.push("");
  let html = ds.map((d) => {
    const ts = S.tasks.filter((t) => (t.dept || "") === d && !(S.hideDone && isDone(t.id)))
      .sort((a, b) => (a.start || "9").localeCompare(b.start || "9"));
    const all = checkables().filter((i) => (i.dept || "") === d);
    const doneN = all.filter((i) => isDone(i.id)).length;
    return `<section class="group" style="--c:${color(d)}"><h3><i></i>${esc(d || "부서 미지정")}<small>${doneN}/${all.length} 완료</small></h3>
      <div class="body">${ts.map(taskCard).join("") || '<div class="empty">표시할 업무가 없습니다.</div>'}</div></section>`;
  }).join("");
  const vacs = S.showVac ? S.vacs.filter((v) => S.dept === "all" || !v.dept || v.dept === S.dept) : [];
  if (vacs.length) html += `<section class="group"><h3>🌴 이번 달 휴가<small>${vacs.length}건</small></h3><div class="body">${vacs.map(vacCard).join("")}</div></section>`;
  if (!html) html = `<div class="empty big">${S.loaded ? "이 달에 등록된 업무가 없습니다. <b>엑셀 업로드</b> 또는 <b>+ 업무 추가</b>로 시작하세요." : "불러오는 중…"}</div>`;
  $("#listView").innerHTML = html;
}

function renderExtra() {
  const undated = S.tasks.filter((t) => !t.start && deptOk(t.dept) && !(S.hideDone && isDone(t.id)));
  const notes = S.notes.filter((n) => deptOk(n.dept));
  let html = "";
  if (S.view === "calendar" && undated.length)
    html += `<section class="group"><h3>날짜 미정 · 상시 업무<small>${undated.length}건</small></h3><div class="body">${undated.map(taskCard).join("")}</div></section>`;
  if (notes.length)
    html += `<section class="group"><h3>공지</h3><ul class="notes">${notes.map((n) => `<li><b style="color:${color(n.dept)}">${esc(n.dept || "")}</b> ${esc(n.text)}</li>`).join("")}</ul></section>`;
  if (S.view === "calendar" && S.loaded && !S.tasks.length && !S.vacs.length)
    html += `<section class="group"><div class="empty big">이 달에 등록된 업무가 없습니다.<br><b>📤 엑셀 업로드</b> 또는 <b>+ 업무 추가</b>로 시작하세요.</div></section>`;
  $("#extra").innerHTML = html;
}

// ───────── 모달 ─────────
function openModal(html, onMount) {
  const m = $("#modal");
  $(".modal-card", m).innerHTML = html;
  m.hidden = false;
  document.body.classList.add("modal-open");
  if (onMount) onMount($(".modal-card", m));
  const first = $(".modal-card input:not([type=hidden]):not([type=checkbox]), .modal-card textarea", m);
  if (first && window.innerWidth > 720) setTimeout(() => first.focus(), 30);
}
function closeModal() { $("#modal").hidden = true; document.body.classList.remove("modal-open"); }

function requireName() {
  if (userName()) return true;
  $(".who").classList.add("need");
  $("#userName").focus();
  toast("먼저 오른쪽 위에 이름을 입력해 주세요.");
  return false;
}

function deptDatalist() {
  return `<datalist id="deptList">${knownDepts().map((d) => `<option value="${esc(d)}">`).join("")}</datalist>`;
}

function deleteRow(label) {
  return `<div class="danger-zone"><button type="button" class="link-danger" data-del>🗑 ${label} 삭제</button>
    <span class="confirm" hidden>정말 삭제할까요? <button type="button" class="btn danger" data-del-yes>삭제</button><button type="button" class="btn" data-del-no>취소</button></span></div>`;
}
function wireDelete(card, fn) {
  const btn = $("[data-del]", card); if (!btn) return;
  btn.onclick = () => { btn.hidden = true; $(".confirm", card).hidden = false; };
  $("[data-del-no]", card).onclick = () => { btn.hidden = false; $(".confirm", card).hidden = true; };
  $("[data-del-yes]", card).onclick = fn;
}

function taskForm(task, date) {
  if (!requireName()) return;
  const t = task || { start: date || S.sel, end: "", dept: S.dept !== "all" ? S.dept : store("myDept") || "", title: "", owner: userName(), memo: "" };
  openModal(`<form class="form" id="taskForm">
    <h2>${task ? "업무 수정" : "업무 추가"}</h2>
    <label>업무 내용 *<textarea name="title" rows="2" required maxlength="300">${esc(t.title)}</textarea></label>
    <div class="row2">
      <label>날짜(시작) *<input type="date" name="start" value="${esc(t.start || "")}" required></label>
      <label>종료일 <small>(하루면 비워두기)</small><input type="date" name="end" value="${esc(t.end && t.end !== t.start ? t.end : "")}"></label>
    </div>
    <div class="row2">
      <label>담당부서 *<input name="dept" list="deptList" value="${esc(t.dept || "")}" required maxlength="30" placeholder="예: 재무팀"></label>
      <label>담당자<input name="owner" value="${esc(t.owner || "")}" maxlength="30"></label>
    </div>
    <label>비고<input name="memo" value="${esc(t.memo || "")}" maxlength="200"></label>
    ${deptDatalist()}
    ${task && (task.subs || []).length ? `<p class="hint">세부 항목 ${task.subs.length}개는 그대로 유지됩니다.</p>` : ""}
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">저장</button></div>
    ${task ? deleteRow("업무") : ""}
  </form>`, (card) => {
    const f = $("#taskForm", card);
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const v = Object.fromEntries(new FormData(f));
      const title = v.title.trim(), dept = v.dept.trim();
      if (!title || !dept || !isISO(v.start)) return;
      if (v.end && v.end < v.start) { toast("종료일이 시작일보다 빠릅니다."); return; }
      const data = { ...(task || {}), title, dept, start: v.start, end: v.end || v.start, owner: v.owner.trim(), memo: v.memo.trim(), dateText: "" };
      if (!task) { data.src = "manual"; data.by = userName(); data.subs = []; }
      // 날짜가 바뀌면 세부항목 날짜 표시 재계산
      (data.subs || []).forEach((s) => { s.own = !!s.start && (s.start !== data.start || (s.end || s.start) !== data.end); });
      busy(f, true);
      try {
        await saveItem("task", data, task && task.id);
        rememberDept(dept); store("myDept", dept);
        closeModal(); toast(task ? "업무를 수정했습니다." : "업무를 추가했습니다.");
        if (!task && !v.start.startsWith(S.month)) setMonth(v.start.slice(0, 7), v.start);
      } catch (e) { console.error(e); toast("저장하지 못했습니다."); busy(f, false); }
    };
    if (task) wireDelete(card, async () => {
      try { await deleteItem(task.id); closeModal(); toast("업무를 삭제했습니다."); } catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
    });
  });
}

function vacForm(vac, date) {
  if (!requireName()) return;
  const v = vac || { name: userName(), dept: store("myDept") || "", start: date || S.sel, end: "", type: "연차", memo: "" };
  openModal(`<form class="form" id="vacForm">
    <h2>${vac ? "휴가 수정" : "휴가 등록"}</h2>
    <div class="row2">
      <label>이름 *<input name="name" value="${esc(v.name)}" required maxlength="20"></label>
      <label>부서<input name="dept" list="deptList" value="${esc(v.dept || "")}" maxlength="30"></label>
    </div>
    <div class="row2">
      <label>시작일 *<input type="date" name="start" value="${esc(v.start || "")}" required></label>
      <label>종료일 <small>(하루면 비워두기)</small><input type="date" name="end" value="${esc(v.end && v.end !== v.start ? v.end : "")}"></label>
    </div>
    <label>종류<select name="type">${VAC_TYPES.map((t) => `<option ${t === v.type ? "selected" : ""}>${t}</option>`).join("")}</select></label>
    <label>메모<input name="memo" value="${esc(v.memo || "")}" maxlength="100" placeholder="예: 업무 대행 홍길동"></label>
    ${deptDatalist()}
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">저장</button></div>
    ${vac ? deleteRow("휴가") : ""}
  </form>`, (card) => {
    const f = $("#vacForm", card);
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const x = Object.fromEntries(new FormData(f));
      if (!x.name.trim() || !isISO(x.start)) return;
      if (x.end && x.end < x.start) { toast("종료일이 시작일보다 빠릅니다."); return; }
      const data = { name: x.name.trim(), dept: x.dept.trim(), start: x.start, end: x.end || x.start, type: x.type, memo: x.memo.trim(), by: vac ? vac.by : userName() };
      busy(f, true);
      try {
        await saveItem("vacation", data, vac && vac.id);
        rememberDept(data.dept);
        closeModal(); toast(vac ? "휴가를 수정했습니다." : "휴가를 등록했습니다.");
        if (!vac && !x.start.startsWith(S.month)) setMonth(x.start.slice(0, 7), x.start);
      } catch (e) { console.error(e); toast("저장하지 못했습니다."); busy(f, false); }
    };
    if (vac) wireDelete(card, async () => {
      try { await deleteItem(vac.id); closeModal(); toast("휴가를 삭제했습니다."); } catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
    });
  });
}
function busy(form, on) { $$("button", form).forEach((b) => (b.disabled = on)); }

// ───────── 엑셀 업로드 ─────────
const HEAD = {
  start: ["일자", "날짜", "시작일", "시작일자", "일정", "완료일", "예정일", "기간"],
  end: ["종료일", "종료일자", "마감일", "끝"],
  title: ["업무내용", "업무내역", "내용", "업무", "업무명", "항목"],
  dept: ["담당부서", "부서", "구분", "팀"],
  owner: ["담당자", "담당", "작성자"],
  memo: ["비고", "메모"],
  due: ["완료기한", "기한"],
};
const norm = (s) => String(s ?? "").replace(/[\s ]/g, "");
const clean = (s) => String(s ?? "").replace(/ /g, " ").replace(/\s+/g, " ").trim();

function serialToISO(n) {
  const d = new Date(Date.UTC(1899, 11, 30) + Math.round(n) * 86400000);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}
function parseDateCell(v, year) {
  if (v === null || v === undefined || v === "") return { start: null, end: null, raw: "" };
  if (typeof v === "number" && v > 20000 && v < 80000) { const d = serialToISO(v); return { start: d, end: d, raw: "" }; }
  const s = clean(v);
  let m;
  const ymd = (y, mo, d) => `${y}-${pad(mo)}-${pad(d)}`;
  if ((m = s.match(/^(\d{4})[-./년]\s*(\d{1,2})[-./월]\s*(\d{1,2})일?\s*[~∼-]\s*(?:(\d{4})[-./년]\s*)?(?:(\d{1,2})[-./월]\s*)?(\d{1,2})일?$/))) {
    const a = ymd(m[1], m[2], m[3]);
    const b = ymd(m[4] || m[1], m[5] || m[2], m[6]);
    return { start: a, end: b >= a ? b : a, raw: "" };
  }
  if ((m = s.match(/^(\d{4})[-./년]\s*(\d{1,2})[-./월]\s*(\d{1,2})/))) { const a = ymd(m[1], m[2], m[3]); return { start: a, end: a, raw: "" }; }
  if ((m = s.match(/^(\d{1,2})[/.월]\s*(\d{1,2})일?\s*(?:\([^)]*\))?\s*(?:[~∼-]\s*(?:(\d{1,2})[/.월]\s*)?(\d{1,2})일?)?$/)) && year) {
    const a = ymd(year, m[1], m[2]);
    const b = m[4] ? ymd(year, m[3] || m[1], m[4]) : a;
    return { start: a, end: b >= a ? b : a, raw: "" };
  }
  return { start: null, end: null, raw: s === "-" ? "" : s };
}

function parseSheet(rows, fileName) {
  // 머리글 행 찾기
  let h = -1, col = {};
  for (let i = 0; i < Math.min(rows.length, 15); i++) {
    const c = {};
    (rows[i] || []).forEach((cell, j) => {
      const n = norm(cell);
      for (const k in HEAD) if (c[k] === undefined && HEAD[k].includes(n)) c[k] = j;
    });
    if (c.title !== undefined) { h = i; col = c; break; }
  }
  if (h < 0) throw new Error("머리글(업무내용/내용 열)을 찾지 못했습니다. 양식을 확인해 주세요.");

  // 연도 추정 (제목/파일명/엑셀 날짜)
  let year = null;
  const yt = (rows.slice(0, h).flat().join(" ") + " " + fileName).match(/(20\d{2})\s*년?/);
  if (yt) year = +yt[1];
  if (!year) for (const r of rows.slice(h + 1)) { const v = r && r[col.start]; if (typeof v === "number" && v > 20000) { year = +serialToISO(v).slice(0, 4); break; } }
  if (!year) year = +TODAY.slice(0, 4);

  const body = rows.slice(h + 1).filter((r) => r && r.some((c) => c !== null && c !== ""));
  const texts = body.map((r) => clean(r[col.title])).filter(Boolean);
  const numbered = texts.filter((t) => /^\d+\s*\./.test(t)).length >= Math.max(2, texts.filter((t) => !/^[-·※\[]/.test(t)).length * 0.4);

  const tasks = [], notes = [], skipped = [];
  let dept = "", baseDept = "", parent = null, child = null;
  const monthCount = {};
  body.forEach((r) => {
    if (col.dept !== undefined && clean(r[col.dept])) {
      const g = clean(r[col.dept]);
      const prev = dept;
      if (/^\(.+\)$/.test(g) && baseDept) dept = `${baseDept}${g}`;
      else { dept = g; baseDept = g; }
      if (dept !== prev) { parent = null; child = null; }
    }
    const t = clean(r[col.title]);
    if (!t) return;
    let d = parseDateCell(col.start !== undefined ? r[col.start] : null, year);
    if (col.end !== undefined) { const e = parseDateCell(r[col.end], year); if (d.start && e.start && e.start >= d.start) d.end = e.start; }
    const due = col.due !== undefined ? parseDateCell(r[col.due], year) : { start: null, raw: "" };
    const memo = col.memo !== undefined ? clean(r[col.memo]) : "";
    const owner = col.owner !== undefined ? clean(r[col.owner]) : "";
    if (d.start) monthCount[d.start.slice(0, 7)] = (monthCount[d.start.slice(0, 7)] || 0) + 1;

    if (t.startsWith("※") && !d.start) { notes.push({ dept, text: t }); return; }
    const looksSub = /^[-·•\[]/.test(t) || (t.startsWith("※") && parent);
    const isParent = !parent || (numbered ? /^\d+\s*\./.test(t) : !looksSub);
    if (isParent) {
      parent = { dept, title: t, start: d.start, end: d.end, dateText: d.start ? "" : d.raw, due: due.start || "", dueText: due.start ? "" : due.raw, memo, owner, subs: [] };
      tasks.push(parent); child = null; return;
    }
    if (!/^[-·•※\[]/.test(t) && child) { child.title += " " + t; return; } // 이어지는 줄
    child = { title: t.replace(/^[-·•]\s*/, ""), start: d.start, end: d.end, dateText: d.start ? "" : d.raw, memo };
    parent.subs.push(child);
  });

  tasks.forEach((p) => {
    if (!p.start) { const ds = p.subs.map((s) => s.end).filter(Boolean).sort(); if (ds.length) p.start = p.end = ds[ds.length - 1]; }
    p.subs.forEach((s) => { s.own = !!s.start && (s.start !== p.start || s.end !== p.end); });
  });
  const mainMonth = Object.entries(monthCount).sort((a, b) => b[1] - a[1])[0];
  return { tasks, notes, mainMonth: mainMonth ? mainMonth[0] : S.month, numbered };
}

async function ensureXLSX() { if (!window.XLSX) await loadScript(XLSX_URL); }

function downloadTemplate() {
  ensureXLSX().then(() => {
    const y = S.month.slice(0, 4), m = S.month.slice(5, 7);
    const aoa = [
      ["일자", "종료일", "담당부서", "업무내용", "담당자", "비고"],
      [`${y}-${m}-05`, "", "재무팀", "10월 매입 마감 및 물품대금 지급", "홍길동", ""],
      [`${y}-${m}-10`, `${y}-${m}-12`, "총무팀", "사내 CCTV 점검", "", "2일간"],
      [`${y}-${m}-15`, "", "총무팀", "- 세부 항목은 앞에 '-'를 붙이면 위 업무에 묶입니다", "", ""],
    ];
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws["!cols"] = [{ wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 48 }, { wch: 10 }, { wch: 16 }];
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "업무계획");
    XLSX.writeFile(wb, "업무계획_양식.xlsx");
  }).catch(() => toast("양식을 만들지 못했습니다. 인터넷 연결을 확인해 주세요."));
}

function uploadForm() {
  if (!requireName()) return;
  openModal(`<div class="form" id="upForm">
    <h2>📤 업무계획 엑셀 업로드</h2>
    <p class="hint">엑셀에 <b>일자 · 업무내용 · 담당부서</b> 열이 있으면 됩니다. (담당자·종료일·비고는 선택)<br>
      기존 '부서 주요 업무계획' 양식(구분/업무내역/완료일)도 그대로 올릴 수 있습니다.</p>
    <div class="up-actions">
      <label class="btn primary file-btn">엑셀 파일 선택<input type="file" id="upFile" accept=".xlsx,.xls,.csv" hidden></label>
      <button type="button" class="btn" id="tplBtn">⬇ 빈 양식 받기</button>
    </div>
    <div id="upPreview"></div>
    <div class="form-actions"><button type="button" class="btn" data-close>닫기</button></div>
  </div>`, (card) => {
    $("#tplBtn", card).onclick = downloadTemplate;
    $("#upFile", card).onchange = async (ev) => {
      const file = ev.target.files[0]; if (!file) return;
      const pv = $("#upPreview", card);
      pv.innerHTML = '<div class="empty">파일을 읽는 중…</div>';
      try {
        await ensureXLSX();
        const wb = XLSX.read(await file.arrayBuffer(), { type: "array" });
        const ws = wb.Sheets[wb.SheetNames[0]];
        const rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: null });
        const res = parseSheet(rows, file.name);
        if (!res.tasks.length) throw new Error("읽을 수 있는 업무가 없습니다.");
        showPreview(card, res, file.name);
      } catch (e) {
        console.error(e);
        pv.innerHTML = `<div class="error-box">${esc(e.message || "파일을 읽지 못했습니다.")}</div>`;
      }
      ev.target.value = "";
    };
  });
}

async function showPreview(card, res, fileName) {
  const pv = $("#upPreview", card);
  const months = [...new Set(res.tasks.flatMap((t) => (t.start ? monthsOf(t.start, t.end) : [res.mainMonth])))].sort();
  const subN = res.tasks.reduce((n, t) => n + t.subs.length, 0);
  const undated = res.tasks.filter((t) => !t.start).length;
  const nodept = res.tasks.filter((t) => !t.dept).length;
  // 기존 엑셀 업무 수 확인
  let existing = [];
  try {
    for (const m of months) {
      const snap = await db.collection("items").where("months", "array-contains", m).get();
      (await readDocs(snap.docs)).forEach((x) => { if ((x.kind === "task" && x.src === "excel") || x.kind === "note") existing.push(x); });
    }
    existing = [...new Map(existing.map((x) => [x.id, x])).values()];
  } catch (e) { console.error(e); }
  const exTasks = existing.filter((x) => x.kind === "task").length;
  const ml = months.map((m) => `${+m.slice(5)}월`).join(", ");
  pv.innerHTML = `
    <div class="up-summary"><b>${esc(fileName)}</b><br>
      ${ml} · 업무 <b>${res.tasks.length}</b>건 (세부 ${subN}건)${res.notes.length ? ` · 공지 ${res.notes.length}건` : ""}
      ${undated ? `<br><span class="warn">날짜를 읽지 못한 업무 ${undated}건은 '날짜 미정'에 들어갑니다.</span>` : ""}
      ${nodept ? `<br><span class="warn">담당부서가 비어 있는 업무 ${nodept}건이 있습니다.</span>` : ""}</div>
    <div class="up-table"><table><thead><tr><th>날짜</th><th>부서</th><th>업무내용</th></tr></thead><tbody>
      ${res.tasks.slice(0, 8).map((t) => `<tr><td>${t.start ? period(t.start, t.end) : esc(t.dateText || "미정")}</td><td>${esc(t.dept)}</td><td>${esc(t.title)}${t.subs.length ? ` <small>(+세부 ${t.subs.length})</small>` : ""}</td></tr>`).join("")}
      ${res.tasks.length > 8 ? `<tr><td colspan="3" class="muted">… 외 ${res.tasks.length - 8}건</td></tr>` : ""}
    </tbody></table></div>
    ${exTasks ? `<div class="up-mode">
      <label><input type="radio" name="mode" value="replace" checked> ${ml} 기존 엑셀 업무 ${exTasks}건을 <b>지우고 교체</b> <small>(그 업무의 체크 기록은 사라집니다. 직접 추가한 업무·휴가는 유지)</small></label>
      <label><input type="radio" name="mode" value="append"> 기존 업무는 두고 <b>추가</b>만</label></div>` : ""}
    <div class="form-actions"><button type="button" class="btn primary" id="upGo">업로드 (${res.tasks.length}건)</button></div>`;
  $("#upGo", pv).onclick = async (ev) => {
    const btn = ev.target;
    const replace = exTasks && ($("input[name=mode]:checked", pv) || {}).value === "replace";
    btn.disabled = true; btn.textContent = "저장 중…";
    try {
      const batchId = new Date().toISOString();
      const writes = [];
      for (const [i, t] of res.tasks.entries()) {
        const id = db.collection("items").doc().id;
        t.subs.forEach((s, j) => { s.id = `${id}~${pad(j + 1)}`; });
        const data = { ...t, src: "excel", file: fileName, batch: batchId, ord: i, by: userName() };
        const months2 = t.start ? monthsOf(t.start, t.end) : [res.mainMonth];
        writes.push({ id, kind: "task", months: months2, data });
      }
      res.notes.forEach((n, i) => writes.push({ id: db.collection("items").doc().id, kind: "note", months: [res.mainMonth], data: { ...n, src: "excel", ord: i } }));
      const ops = [];
      if (replace) existing.forEach((x) => ops.push((b) => b.delete(db.collection("items").doc(x.id))));
      for (const w of writes) {
        const { iv, ct } = await seal(w.data);
        ops.push((b) => b.set(db.collection("items").doc(w.id), { kind: w.kind, months: w.months, iv, ct, at: serverTime() }));
      }
      for (let i = 0; i < ops.length; i += 400) {
        const b = db.batch();
        ops.slice(i, i + 400).forEach((op) => op(b));
        await b.commit();
      }
      res.tasks.forEach((t) => rememberDept(t.dept));
      closeModal();
      toast(`업무 ${res.tasks.length}건을 올렸습니다.`);
      if (res.mainMonth !== S.month) setMonth(res.mainMonth);
    } catch (e) {
      console.error(e); toast("업로드하지 못했습니다."); btn.disabled = false; btn.textContent = "다시 시도";
    }
  };
}

// ───────── 이벤트 ─────────
function setMonth(m, sel) {
  S.month = m;
  S.sel = sel || (TODAY.startsWith(m) ? TODAY : m + "-01");
  render();
  subscribe(m);
}
function shiftMonth(step) {
  let [y, m] = S.month.split("-").map(Number);
  m += step; if (m < 1) { m = 12; y--; } if (m > 12) { m = 1; y++; }
  setMonth(`${y}-${pad(m)}`);
}

function wireEvents() {
  const nameInput = $("#userName");
  nameInput.value = store("userName") || "";
  nameInput.addEventListener("input", () => { store("userName", nameInput.value.trim()); $(".who").classList.remove("need"); });

  document.addEventListener("change", async (ev) => {
    const cb = ev.target.closest("input[data-check]");
    if (!cb) return;
    const id = cb.dataset.check;
    if (!requireName()) { cb.checked = !cb.checked; return; }
    const entry = entries().find((e) => e.id === id) || (() => { const t = S.tasks.find((x) => x.id === id); return t && { id, task: t }; })();
    if (!entry) return;
    const done = cb.checked, prev = S.checks[id];
    S.checks = { ...S.checks, [id]: { done, by: userName(), at: Date.now() } };
    render();
    try { await setCheck(entry, done); }
    catch (e) { console.error(e); S.checks = { ...S.checks, [id]: prev }; render(); toast("저장하지 못했습니다. 인터넷 연결을 확인해 주세요."); }
  });

  document.addEventListener("click", (ev) => {
    const t = ev.target;
    if (t.closest("[data-close]") || t.id === "modal") { closeModal(); return; }
    if (t.closest("#modal")) return;
    let el;
    if ((el = t.closest("[data-edit-task]"))) { ev.preventDefault(); taskForm(S.tasks.find((x) => x.id === el.dataset.editTask)); return; }
    if ((el = t.closest("[data-edit-vac]"))) { vacForm(S.vacs.find((x) => x.id === el.dataset.editVac)); return; }
    if ((el = t.closest("[data-add-task]"))) { taskForm(null, el.dataset.addTask || S.sel); return; }
    if ((el = t.closest("[data-add-vac]"))) { vacForm(null, el.dataset.addVac || S.sel); return; }
    if (t.closest("#uploadBtn")) { uploadForm(); return; }
    if ((el = t.closest("[data-dept]"))) {
      const d = el.dataset.dept;
      S.dept = S.dept === d && d !== "all" ? "all" : d;
      store("dept", S.dept); render(); return;
    }
    if ((el = t.closest("[data-view]"))) { S.view = el.dataset.view; store("view", S.view); render(); return; }
    if (t.closest(".task-chip") && !t.matches("input")) ev.preventDefault();
    const cell = t.closest(".cell[data-date]");
    if (cell && !t.matches("input")) {
      S.sel = cell.dataset.date; render();
      if (window.innerWidth <= 1100) $("#dayPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !$("#modal").hidden) closeModal(); });

  $("#hideDone").addEventListener("change", (e) => { S.hideDone = e.target.checked; store("hideDone", S.hideDone ? "1" : "0"); render(); });
  $("#showVac").addEventListener("change", (e) => { S.showVac = e.target.checked; store("showVac", S.showVac ? "1" : "0"); render(); });
  $("#prevMonth").addEventListener("click", () => shiftMonth(-1));
  $("#nextMonth").addEventListener("click", () => shiftMonth(1));
  $("#todayBtn").addEventListener("click", () => setMonth(TODAY.slice(0, 7), TODAY));
}

// ───────── 시작 ─────────
async function boot() {
  wireEvents();
  render();
  try {
    if (!window.FIREBASE_CONFIG) throw new Error("no config");
    await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VER}/firebase-app-compat.js`);
    await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VER}/firebase-firestore-compat.js`);
    firebase.initializeApp(window.FIREBASE_CONFIG);
    db = firebase.firestore();
  } catch (e) {
    console.error(e);
    setSync("err", "서버에 연결하지 못했습니다");
    return;
  }
  setMonth(S.month, S.sel);
}
