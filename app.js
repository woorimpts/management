"use strict";
/*  부서 업무 달력
 *  - 업무·휴가·체크 기록은 Firestore 에 저장되며, 모두 사이트 비밀번호로 암호화(AES-GCM)됩니다.
 *  - Firestore 컬렉션
 *      items  : { kind: task|vacation|note|personal, months: ["2026-11"], iv, ct, at }
 *               { kind: member,  months: ["member"]  } 직원 이름 목록
 *               { kind: profile, months: ["profile"] } 개인 비밀번호 확인값
 *               { kind: chat,    months: ["chat-2026-11"] } 팀 채팅 메시지 (보낸 달 기준)
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
const stripNum = (t) => String(t ?? "").replace(/^(?:\d+\s*[.)]\s*|\d+\s+)+/, "");
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
async function seal(obj, key = KEY) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, TE.encode(JSON.stringify(obj)));
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}
// 개인 비밀번호 키: 이름별로 고정된 salt(사이트 salt + 이름) → 같은 이름·비밀번호면 항상 같은 키
async function personalKey(name, pw) {
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", TE.encode(window.LOCK.salt + "|personal|" + name)));
  const base = await crypto.subtle.importKey("raw", TE.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: window.LOCK.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
const P = { key: null, name: "", ver: 0 }; // 열려 있는 개인 비밀번호
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
  tasks: [], vacs: [], notes: [], personal: [],
  checks: {},
  loaded: false,
  itemDocs: [],
  dept: store("dept") || "all",
  hideDone: store("hideDone") === "1",
  showVac: store("showVac") !== "0",
  allPersonal: null, // 전체 기간 개인 업무 기록 (null = 아직 못 불러옴 → 이번 달 것만 사용)
  members: [],
  hidePeople: new Set((store("hidePeople") || "").split("|").filter(Boolean)),
  allRange: store("allRange") || "month",
  allOpen: store("allOpen") === "1",
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
    if (!v && P.key && d.kind === "personal") { // 내 개인 비밀번호로 잠긴 일정인지 확인
      const pk = k + ":p" + P.ver;
      v = cache.get(pk);
      if (v === undefined) {
        try { v = { ...JSON.parse(await unseal(d.iv, d.ct, P.key)), private: true }; } catch (e) { v = null; }
        cache.set(pk, v);
      }
    }
    if (v) out.push({ ...v, id: doc.id, kind: d.kind, months: d.months || [] });
  }
  return out;
}

let unsubs = [];
function subscribe(month) {
  unsubs.forEach((u) => u()); unsubs = [];
  S.loaded = false; S.tasks = []; S.vacs = []; S.notes = []; S.personal = []; S.checks = {}; S.itemDocs = [];
  setSync("", "불러오는 중…");
  let gotItems = false, gotChecks = false;
  const done = () => { if (gotItems && gotChecks) { S.loaded = true; setSync("live", "실시간 공유 중"); } render(); };
  const onErr = (e) => { console.error(e); setSync("err", "연결 오류 — 새로고침 해주세요"); };

  unsubs.push(db.collection("items").where("months", "array-contains", month).onSnapshot(async (snap) => {
    S.itemDocs = snap.docs;
    await processItems(month);
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
// 달과 상관없는 구독: 직원 목록, 전체 개인 업무 기록
let personalDocs = [];
function subscribeGlobal() {
  db.collection("items").where("months", "array-contains", "member").onSnapshot(async (snap) => {
    S.members = (await readDocs(snap.docs)).filter((x) => x.kind === "member" && x.name);
    render();
  }, (e) => console.error(e));
  db.collection("items").where("kind", "==", "personal").onSnapshot(async (snap) => {
    personalDocs = snap.docs;
    await processPersonal(); render();
  }, (e) => { console.error(e); S.allPersonal = null; render(); });
}
const byStart = (a, b) => (a.start || "").localeCompare(b.start || "") || (a.title || "").localeCompare(b.title || "");
async function processPersonal() {
  S.allPersonal = (await readDocs(personalDocs)).filter((x) => x.kind === "personal").sort(byStart);
}
async function processItems(month) {
  const list = await readDocs(S.itemDocs);
  if (S.month !== month) return;
  S.tasks = list.filter((x) => x.kind === "task").sort(taskOrder);
  S.vacs = list.filter((x) => x.kind === "vacation").sort((a, b) => (a.start || "").localeCompare(b.start || "") || (a.name || "").localeCompare(b.name || ""));
  // 직접 등록한 공지가 위, 엑셀 공지는 엑셀 순서대로
  S.notes = list.filter((x) => x.kind === "note").sort((a, b) => (a.src === "excel") - (b.src === "excel") || (a.ord ?? 0) - (b.ord ?? 0) || (a.start || "").localeCompare(b.start || ""));
  S.personal = list.filter((x) => x.kind === "personal").sort(byStart);
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

// 개인 일정: 비공개면 개인 비밀번호 키로, 공개면 사이트 키로 암호화
async function savePersonal(data, id) {
  const { id: _i, kind: _k, months: _m, private: priv, ...plain } = data;
  if (priv && !P.key) throw new Error("locked");
  const { iv, ct } = await seal(plain, priv ? P.key : KEY);
  const payload = { kind: "personal", months: monthsOf(data.start, data.end), iv, ct, at: serverTime() };
  if (id) await db.collection("items").doc(id).set(payload);
  else await db.collection("items").add(payload);
}

// 개인 비밀번호 확인용 프로필 (이름 → 검증값). 내용은 사이트 키로 암호화
async function loadProfiles(name) {
  const snap = await db.collection("items").where("months", "array-contains", "profile").get();
  const list = await readDocs(snap.docs);
  return list.filter((p) => p.kind === "profile" && p.name === name);
}
async function unlockPersonal(name, pw, remember) {
  const key = await personalKey(name, pw);
  const profiles = await loadProfiles(name);
  if (profiles.length) {
    let ok = false;
    for (const p of profiles) { try { await unseal(p.viv, p.vct, key); ok = true; break; } catch (e) {} }
    if (!ok) return "wrong";
  } else {
    const v = await seal("personal-ok", key);
    const { iv, ct } = await seal({ name, viv: v.iv, vct: v.ct });
    await db.collection("items").add({ kind: "profile", months: ["profile"], iv, ct, at: serverTime() });
  }
  P.key = key; P.name = name; P.ver++;
  store("pPw:" + name, remember ? pw : null);
  await processItems(S.month); await processPersonal(); render();
  return "ok";
}
function lockPersonal() {
  if (P.name) store("pPw:" + P.name, null);
  P.key = null; P.name = ""; P.ver++;
  S.personal = S.personal.filter((x) => !x.private);
  if (S.allPersonal) S.allPersonal = S.allPersonal.filter((x) => !x.private);
  render();
}
async function hasProfile(name) { try { return (await loadProfiles(name)).length > 0; } catch (e) { return false; } }
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
// 화면에 보이는 부서 순서. 여기 없는 부서는 그 뒤에 등장 순서대로
const DEPT_ORDER = ["총괄", "총무팀(인사)", "총무팀(총무)", "재무팀"];
let DEPTS = [], COLOR_DEPTS = [];
function computeDepts() {
  const ds = [];
  S.tasks.forEach((t) => { if (t.dept && !ds.includes(t.dept)) ds.push(t.dept); });
  S.vacs.forEach((v) => { if (v.dept && !ds.includes(v.dept)) ds.push(v.dept); });
  COLOR_DEPTS = ds; // 색상은 기존처럼 등장 순서로 (순서를 바꿔도 부서 색은 그대로)
  const rank = (d) => (DEPT_ORDER.includes(d) ? DEPT_ORDER.indexOf(d) : DEPT_ORDER.length + ds.indexOf(d));
  DEPTS = [...ds].sort((a, b) => rank(a) - rank(b));
  if (S.dept !== "all" && !ds.includes(S.dept) && S.loaded) S.dept = "all";
}
const color = (dept) => (COLOR_DEPTS.includes(dept) ? `var(--d${COLOR_DEPTS.indexOf(dept) % 8})` : "var(--d-none)");
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
// 확인 필요: 체크가 안 됐는데 마감일이 오늘이거나 지난 업무 → 맨 위로 올리고 깜빡임
const isUrgent = (e) => !isDone(e.id) && !!e.end && e.end <= TODAY;
const pUrgent = (p) => !p.done && !!p.start && (p.end || p.start) <= TODAY;
// 표시 순서: ① 깜빡이는 업무(오늘 마감·기한 지남, 미체크) ② 체크 안 한 업무 ③ 체크한 업무(맨 아래)
const taskRank = (e) => (isUrgent(e) ? 0 : isDone(e.id) ? 2 : 1);
const pRank = (p) => (pUrgent(p) ? 0 : p.done ? 2 : 1);
const urgTag = (end) => `<b class="urg">${end < TODAY ? "지남" : "오늘"}</b>`;
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
const isMine = (p) => p.name && p.name === userName();
// ── 개인별 업무 기록: 사람 목록 / 색 / 표시 여부 ──
const personOn = (name) => !S.hidePeople.has(name);
// 사람 색: 이름별로 정해진 자리에서 시작해 아직 안 쓴 색을 배정 (8명까지는 겹치지 않음, 누가 보든 같은 색)
let personColors = new Map(), colorKey = "";
function personColor(name) {
  // 보는 사람의 이름은 빼고 계산해야 누가 보든 색이 같음
  const names = [...new Set([...S.members.map((m) => m.name), ...allPersonal().map((r) => r.name), name].filter(Boolean))].sort((a, b) => a.localeCompare(b, "ko"));
  const key = names.join("|");
  if (key !== colorKey) {
    colorKey = key; personColors = new Map();
    const used = new Set();
    names.forEach((n) => {
      let h = 0;
      for (const c of n) h = (h * 31 + c.codePointAt(0)) >>> 0;
      let i = h % 8;
      for (let k = 0; k < 8 && used.has(i); k++) i = (i + 1) % 8;
      used.add(i); if (used.size >= 8) used.clear();
      personColors.set(n, `var(--d${i})`);
    });
  }
  return personColors.get(name) || "var(--d-none)";
}
const initial = (name) => String(name).trim().slice(-2);
const allPersonal = () => S.allPersonal || S.personal;
function people() {
  const map = new Map();
  const add = (name, dept, member) => {
    if (!name) return;
    const p = map.get(name) || { name, dept: "", member: null };
    if (dept && !p.dept) p.dept = dept;
    if (member) p.member = member;
    map.set(name, p);
  };
  S.members.forEach((m) => add(m.name, m.dept, m));
  allPersonal().forEach((r) => add(r.name, r.dept));
  add(userName(), store("myDept") || "");
  const me = userName();
  return [...map.values()].sort((a, b) => (b.name === me) - (a.name === me) || a.name.localeCompare(b.name, "ko"));
}
function savePeopleFilter() { store("hidePeople", [...S.hidePeople].join("|")); }
function dayPersonal(date) {
  return S.personal.filter((p) => p.start <= date && date <= (p.end || p.start) && personOn(p.name) && !(S.hideDone && p.done));
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
  const lb = $("#pLockBtn");
  lb.textContent = P.key ? `🔓 ${P.name} 비공개 열림` : "🔒 내 비공개 기록 열기";
  lb.classList.toggle("on", !!P.key);
  $$(".seg button").forEach((b) => b.classList.toggle("on", b.dataset.view === S.view));
  $("#calendarView").hidden = S.view !== "calendar";
  $("#listView").hidden = S.view !== "list";
  renderSummary();
  renderFilters();
  if (S.view === "calendar") { renderCalendar(); renderPanel(); renderPeople(); renderAllPersonal(); } else renderList();
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
      <div class="late" title="${late ? `기한 지남 ${late}건` : ""}">${late ? `지남 ${late}` : ""}</div></button>`;
  }).join("");
  const vacDays = new Set();
  S.vacs.forEach((v) => { if (S.dept === "all" || v.dept === S.dept) vacDays.add(v.name); });
  html += `<div class="stat vac-stat"><div class="name">🌴 이번 달 휴가</div><div class="num">${vacDays.size}<small>명</small></div>
    <div class="late muted">${S.vacs.filter((v) => v.start <= TODAY && TODAY <= (v.end || v.start)).length ? `오늘 ${S.vacs.filter((v) => v.start <= TODAY && TODAY <= (v.end || v.start)).length}명` : ""}</div></div>`;
  if (userName()) {
    const mine = S.personal.filter(isMine);
    const md2 = mine.filter((p) => p.done).length;
    const pct = mine.length ? Math.round((md2 / mine.length) * 100) : 0;
    html += `<button class="stat me-stat" data-add-personal="" style="--c:var(--me)" title="눌러서 개인 업무 기록 추가"><div class="name">📝 내 기록</div>
      <div class="num">${mine.length ? pct + "%" : "–"}<small>${md2}/${mine.length}</small></div>
      <div class="bar"><span style="width:${pct}%"></span></div>
      <div class="late muted">${mine.filter((p) => p.private).length ? `🔒${mine.filter((p) => p.private).length}` : ""}</div></button>`;
  }
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
    const list = dayEntries(ds).sort((a, b) => taskRank(a) - taskRank(b));
    const vacs = dayVacs(ds);
    const doneN = list.filter((e) => isDone(e.id)).length;
    const lateN = list.filter(isLate).length;
    const countCls = lateN ? "late" : list.length && doneN === list.length ? "all" : "";
    const count = list.length ? `<span class="dcount ${countCls}">${doneN}/${list.length}</span>` : "";
    const vacHtml = vacs.length ? `<div class="vac-line" title="${esc(vacs.map(vacLabel).join(", "))}">🌴 ${esc(vacs.slice(0, 3).map(vacLabel).join(", "))}${vacs.length > 3 ? ` 외 ${vacs.length - 3}` : ""}</div>` : "";
    const pers = dayPersonal(ds).sort((a, b) => pRank(a) - pRank(b) || isMine(b) - isMine(a));
    const total = vacs.length ? 3 : 4;
    // 부서 업무 먼저, 개인 기록은 최소 1칸
    const budget = Math.min(list.length, pers.length ? total - 1 : total);
    const pShow = pers.slice(0, Math.max(1, total - budget));
    const pChips = pShow.map((p) => `<label class="task-chip pchip ${p.done ? "done" : ""} ${isMine(p) ? "mine" : ""} ${pUrgent(p) ? "urgent" : ""}" style="--c:${personColor(p.name)}" title="${esc(p.name + " · " + p.title)}">
        <input type="checkbox" data-pcheck="${esc(p.id)}" ${p.done ? "checked" : ""} ${isMine(p) ? "" : "disabled"}><i class="av-s">${esc(initial(p.name).slice(-1))}</i>${pUrgent(p) ? urgTag(p.end || p.start) : ""}<span>${p.private ? "🔒" : ""}${esc(p.title)}</span></label>`).join("");
    const chips = list.slice(0, budget).map((e) => {
      const done = isDone(e.id);
      return `<label class="task-chip ${done ? "done" : ""} ${isLate(e) ? "late" : ""} ${isUrgent(e) ? "urgent" : ""}" style="--c:${color(e.task.dept)}" title="${esc(e.task.dept + " · " + (e.sub ? stripNum(e.task.title) + " › " : "") + e.title)}">
        <input type="checkbox" data-check="${esc(e.id)}" ${done ? "checked" : ""}>${isUrgent(e) ? urgTag(e.end) : ""}<span>${esc(stripNum(e.title))}</span></label>`;
    }).join("");
    const hidden = list.length - Math.min(list.length, budget) + (pers.length - pShow.length);
    const more = hidden > 0 ? `<div class="more">+${hidden}건 더보기</div>` : "";
    const dots = `<div class="dots">${vacs.length ? '<i class="vac"></i>' : ""}${pers.slice(0, 3).map((p) => `<i class="me" style="--c:${personColor(p.name)}"></i>`).join("")}${list.slice(0, 7).map((e) => `<i style="--c:${color(e.task.dept)}" class="${isDone(e.id) ? "done" : ""}"></i>`).join("")}</div>`;
    html += `<div class="${cls}" data-date="${ds}"><div class="dhead"><span class="dnum">${d.getDate()}</span>${count}</div>${vacHtml}${chips}${pChips}${more}${dots}</div>`;
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
  const dueToday = !done && t.start && (t.end || t.start) === TODAY;
  const meta = [
    `<span class="dept">${esc(t.dept || "부서 미지정")}</span>`,
    t.start ? `<span>📅 ${period(t.start, t.end)}</span>` : t.dateText ? `<span>📅 ${esc(t.dateText)}</span>` : "",
    t.owner ? `<span>👤 ${esc(t.owner)}</span>` : "",
    t.due ? `<span>기한 ${mdw(t.due)}</span>` : t.dueText ? `<span>${esc(t.dueText)}</span>` : "",
    t.memo ? `<span>비고: ${esc(t.memo)}</span>` : "",
    late ? `<span class="late">기한 지남</span>` : dueToday ? `<span class="late">오늘 마감</span>` : "",
    checkInfo(t.id),
  ].join("");
  const subs = (t.subs || []).length ? `<ul class="subs">${t.subs.map((s) => {
    if (!s.own) return `<li><span class="t">${esc(s.title)}${s.dateText ? ` (${esc(s.dateText)})` : ""}</span></li>`;
    const sd = isDone(s.id);
    return `<li class="chk ${sd ? "done" : ""}"><input type="checkbox" data-check="${esc(s.id)}" ${sd ? "checked" : ""}>
      <span><span class="t">${esc(s.title)}</span> <span class="sd">${period(s.start, s.end)}</span> ${checkInfo(s.id)}</span></li>`;
  }).join("")}</ul>` : "";
  const added = t.src === "manual" && t.by ? `<span class="added">${esc(t.by)} 추가</span>` : "";
  return `<div class="task ${done ? "done" : ""} ${late || dueToday ? "urgent" : ""}" style="--c:${color(t.dept)}">
    <button class="edit-btn" data-edit-task="${esc(t.id)}" title="수정/삭제" aria-label="수정">✎</button>
    <label class="task-row"><input type="checkbox" data-check="${esc(t.id)}" ${done ? "checked" : ""}>
      <div><div class="task-title">${esc(stripNum(t.title))}</div><div class="meta">${meta}${added}</div></div></label>${subs}</div>`;
}

function subCard(e) {
  const s = e.sub, t = e.task, done = isDone(s.id);
  return `<div class="task ${done ? "done" : ""} ${isUrgent(e) ? "urgent" : ""}" style="--c:${color(t.dept)}">
    <button class="edit-btn" data-edit-task="${esc(t.id)}" title="수정/삭제" aria-label="수정">✎</button>
    <div class="parent-ref">${esc(stripNum(t.title))} ›</div>
    <label class="task-row"><input type="checkbox" data-check="${esc(s.id)}" ${done ? "checked" : ""}>
      <div><div class="task-title">${esc(s.title)}</div>
      <div class="meta"><span class="dept">${esc(t.dept)}</span><span>📅 ${period(s.start, s.end)}</span>${isLate(e) ? '<span class="late">기한 지남</span>' : isUrgent(e) ? '<span class="late">오늘 마감</span>' : ""}${checkInfo(s.id)}</div></div></label></div>`;
}

function vacCard(v) {
  return `<div class="vac-card">
    <div><b>🌴 ${esc(v.name)}</b> <span class="vac-type">${esc(v.type || "휴가")}</span>
    <div class="meta">${v.dept ? `<span>${esc(v.dept)}</span>` : ""}<span>📅 ${period(v.start, v.end)}</span>${v.memo ? `<span>${esc(v.memo)}</span>` : ""}</div></div>
    <button class="edit-btn" data-edit-vac="${esc(v.id)}" title="수정/삭제" aria-label="수정">✎</button></div>`;
}

function personalCard(p) {
  const mine = isMine(p);
  const urg = pUrgent(p);
  return `<div class="task pcard ${p.done ? "done" : ""} ${mine ? "mine" : ""} ${urg ? "urgent" : ""}" style="--c:${personColor(p.name)}">
    ${mine ? `<button class="edit-btn" data-edit-personal="${esc(p.id)}" title="수정/삭제" aria-label="수정">✎</button>` : ""}
    <label class="task-row"><input type="checkbox" data-pcheck="${esc(p.id)}" ${p.done ? "checked" : ""} ${mine ? "" : "disabled"}>
      <div><div class="task-title">${esc(p.title)}</div>
      <div class="meta"><span class="pname">${p.private ? "🔒 비공개 · " : ""}${esc(p.name)}</span><span>📅 ${period(p.start, p.end)}</span>${urg ? `<span class="late">${(p.end || p.start) < TODAY ? "기한 지남" : "오늘 마감"}</span>` : ""}${p.memo ? `<span>${esc(p.memo)}</span>` : ""}${p.done && p.doneAt ? `<span class="by">✓ 완료</span>` : ""}</div></div></label></div>`;
}

function renderPanel() {
  const d = S.sel && S.sel.startsWith(S.month) ? S.sel : S.month + "-01";
  const list = dayEntries(d).sort((a, b) => taskRank(a) - taskRank(b));
  const vacs = dayVacs(d);
  const pers = dayPersonal(d).sort((a, b) => pRank(a) - pRank(b) || isMine(b) - isMine(a));
  const doneN = list.filter((e) => isDone(e.id)).length;
  const [, m, day] = d.split("-");
  $("#dayPanel").innerHTML = `<div class="panel-head">
      <div><h2>${+m}월 ${+day}일 (${WEEK[dow(d)]})${d === TODAY ? " · 오늘" : ""}</h2>
      <p>${list.length ? `업무 ${list.length}건 · 완료 ${doneN}건` : "업무 없음"}${vacs.length ? ` · 휴가 ${vacs.length}명` : ""}${pers.length ? ` · 개인 기록 ${pers.length}건` : ""}</p></div>
      <div class="panel-actions"><button class="small-btn" data-add-task="${d}">+ 업무</button><button class="small-btn me" data-add-personal="${d}">+ 개인기록</button><button class="small-btn vac" data-add-vac="${d}">+ 휴가</button></div></div>
    <div class="panel-body">
      ${vacs.length ? `<div class="sec-title">휴가</div>${vacs.map(vacCard).join("")}` : ""}
      ${vacs.length || pers.length ? `<div class="sec-title">부서 업무</div>` : ""}
      ${!S.loaded ? '<div class="empty">불러오는 중…</div>' : list.length ? list.map((e) => (e.sub ? subCard(e) : taskCard(e.task))).join("") : '<div class="empty">이 날 마감인 업무가 없습니다.<br>위의 <b>+ 업무</b>로 추가할 수 있습니다.</div>'}
      ${pers.length ? `<div class="sec-title">개인 업무 기록</div>${pers.map(personalCard).join("")}` : ""}
    </div>`;
}

// ───────── 개인별 업무 기록 (사람 목록) ─────────
function renderPeople() {
  const list = people(), me = userName(), recs = allPersonal();
  const rows = list.map((p) => {
    const mine = recs.filter((r) => r.name === p.name);
    const done = mine.filter((r) => r.done).length;
    const canDel = p.member && !mine.length && p.name !== me;
    return `<div class="person ${p.name === me ? "me" : ""}" style="--c:${personColor(p.name)}">
      <label><input type="checkbox" data-person="${esc(p.name)}" ${personOn(p.name) ? "checked" : ""}>
        <span class="av">${esc(initial(p.name))}</span>
        <span class="nm">${esc(p.name)}${p.dept ? `<small>${esc(p.dept)}</small>` : ""}</span></label>
      <span class="cnt" title="완료 / 전체">${done}/${mine.length}</span>
      ${p.name === me ? `<button class="small-btn me" data-add-personal="" title="내 업무 기록 추가">+</button>`
        : canDel ? `<button class="edit-btn" data-del-member="${esc(p.member.id)}" title="목록에서 빼기" aria-label="목록에서 빼기">✕</button>` : ""}
    </div>`;
  }).join("");
  // 다른 사람 변경으로 다시 그려져도 입력 중이던 새 이름은 유지
  const oldInput = $("#memberForm input"), typed = oldInput ? oldInput.value : "", focused = oldInput && document.activeElement === oldInput;
  $("#peoplePanel").innerHTML = `<div class="panel-head"><div><h2>👥 개인별 업무 기록</h2><p>체크한 사람의 기록이 달력에 함께 표시됩니다</p></div></div>
    <div class="quick"><button data-people="all">모두 보기</button>·<button data-people="none">모두 끄기</button>·<button data-people="me">나만 보기</button></div>
    <div class="people-list">${rows || '<div class="empty">아직 등록된 사람이 없습니다.</div>'}</div>
    <form class="people-foot" id="memberForm" autocomplete="off"><input name="name" placeholder="새 이름 추가 (예: 홍길동)" maxlength="20" aria-label="새 이름"><button class="small-btn">+ 추가</button></form>`;
  const ni = $("#memberForm input");
  ni.value = typed;
  if (focused) ni.focus();
}

function weekRange(date) {
  const d = new Date(date + "T00:00"), s = new Date(d); s.setDate(d.getDate() - d.getDay());
  const e = new Date(s); e.setDate(s.getDate() + 6);
  return [iso(s), iso(e)];
}
function renderAllPersonal() {
  const range = S.allRange;
  let from = "", to = "9999";
  if (range === "month") { from = S.month + "-01"; to = S.month + "-31"; }
  else if (range === "week") [from, to] = weekRange(TODAY);
  const on = people().filter((p) => personOn(p.name));
  const recs = allPersonal().filter((r) => r.start <= to && (r.end || r.start) >= from);
  let total = 0, doneT = 0;
  const groups = on.map((p) => {
    const mine = recs.filter((r) => r.name === p.name);
    const done = mine.filter((r) => r.done).length; total += mine.length; doneT += done;
    const rows = mine.filter((r) => !(S.allOpen && r.done)).sort((a, b) => pRank(a) - pRank(b)).map((r) => {
      const end = r.end || r.start;
      const cls = [r.done && "done", !r.done && end < TODAY && "late", r.start <= TODAY && TODAY <= end && "today"].filter(Boolean).join(" ");
      return `<div class="all-row ${cls}">
        <input type="checkbox" data-pcheck="${esc(r.id)}" ${r.done ? "checked" : ""} ${isMine(r) ? "" : "disabled"} aria-label="완료">
        <button class="all-go" data-go="${esc(r.start)}" title="${esc(r.title)}${r.memo ? " — " + esc(r.memo) : ""}"><span class="dt">${end !== r.start ? `${md(r.start)}~${md(end)}` : mdw(r.start)}</span><span class="tt">${r.private ? "🔒 " : ""}${esc(r.title)}</span></button>
      </div>`;
    }).join("") || '<div class="all-none">표시할 기록 없음</div>';
    return `<div class="all-group" style="--c:${personColor(p.name)}"><h4><span class="av">${esc(initial(p.name).slice(-1))}</span>${esc(p.name)}<small>완료 ${done}/${mine.length}</small></h4>${rows}</div>`;
  }).join("");
  const label = { month: `${+S.month.slice(5)}월`, week: "이번 주", all: "전체 기간" }[range];
  $("#allPanel").innerHTML = `<div class="panel-head"><div><h2>📋 개인별 업무 전체 목록</h2>
      <p>${label} · ${on.length}명 · ${total}건 중 ${doneT}건 완료${!S.allPersonal && range !== "month" ? " · (이번 달만 불러옴)" : ""}</p></div></div>
    <div class="quick"><label class="switch"><input type="checkbox" id="allOpen" ${S.allOpen ? "checked" : ""}><span>미완료만</span></label>
      <select id="allRange" aria-label="기간">${[["month", "보고 있는 달"], ["week", "이번 주"], ["all", "전체 기간"]].map(([v, t]) => `<option value="${v}" ${v === range ? "selected" : ""}>${t}</option>`).join("")}</select></div>
    <div class="all-list">${on.length ? groups : '<div class="empty">위 목록에서 사람을 체크하세요.</div>'}</div>`;
}

function renderList() {
  const ds = DEPTS.filter((d) => deptOk(d) && S.tasks.some((t) => t.dept === d));
  if (S.tasks.some((t) => !t.dept) && S.dept === "all") ds.push("");
  let html = ds.map((d) => {
    const ts = S.tasks.filter((t) => (t.dept || "") === d && !(S.hideDone && isDone(t.id)))
      .sort((a, b) => isDone(a.id) - isDone(b.id) || (a.start || "9").localeCompare(b.start || "9"));
    const all = checkables().filter((i) => (i.dept || "") === d);
    const doneN = all.filter((i) => isDone(i.id)).length;
    return `<section class="group" style="--c:${color(d)}"><h3><i></i>${esc(d || "부서 미지정")}<small>${doneN}/${all.length} 완료</small></h3>
      <div class="body">${ts.map(taskCard).join("") || '<div class="empty">표시할 업무가 없습니다.</div>'}</div></section>`;
  }).join("");
  const vacs = S.showVac ? S.vacs.filter((v) => S.dept === "all" || !v.dept || v.dept === S.dept) : [];
  if (vacs.length) html += `<section class="group"><h3>🌴 이번 달 휴가<small>${vacs.length}건</small></h3><div class="body">${vacs.map(vacCard).join("")}</div></section>`;
  const pers = S.personal.filter((p) => personOn(p.name) && !(S.hideDone && p.done)).sort((a, b) => pRank(a) - pRank(b) || isMine(b) - isMine(a) || (a.start || "").localeCompare(b.start || ""));
  if (pers.length) html += `<section class="group me-group"><h3>📝 개인 업무 기록<small>${pers.length}건</small></h3><div class="body">${pers.map(personalCard).join("")}</div></section>`;
  if (!html) html = `<div class="empty big">${S.loaded ? "이 달에 등록된 업무가 없습니다. <b>엑셀 업로드</b> 또는 <b>+ 업무 추가</b>로 시작하세요." : "불러오는 중…"}</div>`;
  $("#listView").innerHTML = html;
}

function renderExtra() {
  const undated = S.tasks.filter((t) => !t.start && deptOk(t.dept) && !(S.hideDone && isDone(t.id))).sort((a, b) => isDone(a.id) - isDone(b.id));
  const notes = S.notes.filter((n) => deptOk(n.dept));
  let html = "";
  if (S.view === "calendar" && undated.length)
    html += `<section class="group"><h3>날짜 미정 · 상시 업무<small>${undated.length}건</small></h3><div class="body">${undated.map(taskCard).join("")}</div></section>`;
  if (notes.length)
    html += `<section class="group"><h3>📢 공지<small>${notes.length}건</small></h3><ul class="notes">${notes.map((n) =>
      `<li><span><b style="color:${color(n.dept)}">${esc(n.dept || "")}</b> ${esc(n.text)}${n.by ? ` <span class="by">${esc(n.by)}</span>` : ""}</span>
        <button class="edit-btn" data-edit-note="${esc(n.id)}" title="수정/삭제" aria-label="수정">✎</button></li>`).join("")}</ul></section>`;
  if (S.view === "calendar" && S.loaded && !S.tasks.length && !S.vacs.length)
    html += `<section class="group"><div class="empty big">이 달에 등록된 업무가 없습니다.<br><b>📤 엑셀 업로드</b> 또는 <b>+ 업무 추가</b>로 시작하세요.</div></section>`;
  const extra = $("#extra");
  extra.innerHTML = html;
  // 달력 보기에서는 달력 바로 아래(왼쪽 열), 목록 보기에서는 목록 아래에 표시
  const host = S.view === "calendar" ? $("#mainCol") : $("#listView").parentNode;
  if (S.view === "calendar") { if (extra.parentNode !== host) host.appendChild(extra); }
  else if (extra.previousElementSibling !== $("#listView")) $("#listView").after(extra);
}

// ───────── 모달 ─────────
function openModal(html, onMount) {
  const m = $("#modal");
  $(".modal-card", m).innerHTML = html;
  m.hidden = false;
  document.body.classList.add("modal-open");
  if (onMount) onMount($(".modal-card", m));
  deptCombo($(".modal-card", m));
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

// 부서 입력칸: 누르면 부서 목록, 글자를 치면 그 글자가 들어간 부서만 보여줌 (예: '재' → 재무팀)
function deptCombo(card) {
  $$("input[data-dept-combo]", card).forEach((input) => {
    const pop = document.createElement("ul");
    pop.className = "dept-pop"; pop.hidden = true; pop.setAttribute("role", "listbox");
    input.after(pop);
    let items = [], cur = -1;
    const show = () => {
      const q = input.value.trim();
      items = knownDepts().filter((d) => d.includes(q) && d !== q);
      cur = -1;
      pop.innerHTML = items.map((d, i) => `<li role="option" data-i="${i}">${esc(d)}</li>`).join("");
      pop.hidden = !items.length;
    };
    const pick = (i) => { input.value = items[i]; pop.hidden = true; };
    const mark = () => $$("li", pop).forEach((li, i) => li.classList.toggle("on", i === cur));
    input.addEventListener("input", show);
    input.addEventListener("focus", show);
    input.addEventListener("blur", () => setTimeout(() => (pop.hidden = true), 150));
    pop.addEventListener("mousedown", (ev) => { const li = ev.target.closest("li"); if (li) { ev.preventDefault(); pick(+li.dataset.i); } });
    input.addEventListener("keydown", (ev) => {
      if (pop.hidden || ev.isComposing) return;
      if (ev.key === "ArrowDown") { cur = (cur + 1) % items.length; mark(); ev.preventDefault(); }
      else if (ev.key === "ArrowUp") { cur = (cur - 1 + items.length) % items.length; mark(); ev.preventDefault(); }
      else if (ev.key === "Enter" && cur >= 0) { pick(cur); ev.preventDefault(); }
      else if (ev.key === "Escape") { pop.hidden = true; ev.stopPropagation(); }
    });
  });
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

function subRow(s, idx) {
  return `<div class="sub-row" data-idx="${idx}">
    <input data-f="title" value="${esc(s ? s.title : "")}" maxlength="300" placeholder="세부 항목 내용" aria-label="세부 항목 내용">
    <input type="date" data-f="start" value="${esc(s && s.start || "")}" aria-label="시작일">
    <input type="date" data-f="end" value="${esc(s && s.end && s.end !== s.start ? s.end : "")}" aria-label="종료일">
    <button type="button" class="edit-btn" data-sub-del title="삭제" aria-label="세부 항목 삭제">✕</button>
  </div>`;
}

function taskForm(task, date) {
  if (!requireName()) return;
  // 위쪽 '+ 업무 추가'는 날짜 없이 열림(비워 두면 날짜 미정), 날짜 패널의 '+ 업무'는 그 날짜가 채워짐
  const t = task || { start: date || "", end: "", dept: "", title: "", owner: userName(), memo: "" };
  openModal(`<form class="form" id="taskForm">
    <h2>${task ? "업무 수정" : "업무 추가"}</h2>
    <label>업무 내용 *<textarea name="title" rows="2" required maxlength="300">${esc(stripNum(t.title))}</textarea></label>
    <div class="row2">
      <label>날짜(시작) <small>(비우면 날짜 미정)</small><input type="date" name="start" value="${esc(t.start || "")}"></label>
      <label>종료일 <small>(하루면 비워두기)</small><input type="date" name="end" value="${esc(t.end && t.end !== t.start ? t.end : "")}"></label>
    </div>
    <div class="row2">
      <label>담당부서 *<input name="dept" data-dept-combo autocomplete="off" value="${esc(t.dept || "")}" required maxlength="30" placeholder="예: 재무팀"></label>
      <label>담당자<input name="owner" value="${esc(t.owner || "")}" maxlength="30"></label>
    </div>
    <label>비고<input name="memo" value="${esc(t.memo || "")}" maxlength="200"></label>
    <div class="sub-edit">
      <div class="sub-edit-head">세부 항목 <small>(날짜를 비우면 업무 날짜를 따릅니다)</small></div>
      <div id="subRows">${(t.subs || []).map((s, i) => subRow(s, i)).join("")}</div>
      <button type="button" class="small-btn" data-sub-add>+ 세부 항목 추가</button>
    </div>
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">저장</button></div>
    ${task ? deleteRow("업무") : ""}
  </form>`, (card) => {
    const f = $("#taskForm", card);
    card.addEventListener("click", (ev) => {
      if (ev.target.closest("[data-sub-add]")) {
        $("#subRows", card).insertAdjacentHTML("beforeend", subRow(null, ""));
        $("#subRows .sub-row:last-child input", card).focus();
      } else if (ev.target.closest("[data-sub-del]")) ev.target.closest(".sub-row").remove();
    });
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const v = Object.fromEntries(new FormData(f));
      const title = v.title.trim(), dept = v.dept.trim();
      if (!title || !dept) return;
      const dated = isISO(v.start);
      if (v.start && !dated) { toast("날짜 형식이 올바르지 않습니다."); return; }
      if (!dated && v.end) { toast("종료일만 있고 시작일이 없습니다. 시작일을 넣거나 종료일을 비워 주세요."); return; }
      if (v.end && v.end < v.start) { toast("종료일이 시작일보다 빠릅니다."); return; }
      const id = task ? task.id : db.collection("items").doc().id;
      // 세부 항목: 기존 항목은 id를 유지해야 체크 기록이 이어짐
      const subs = [];
      for (const row of $$(".sub-row", f)) {
        const st = $("[data-f=title]", row).value.trim(), ss = $("[data-f=start]", row).value, se = $("[data-f=end]", row).value;
        if (!st) continue;
        if (ss && se && se < ss) { toast(`세부 항목 '${st}'의 종료일이 시작일보다 빠릅니다.`); return; }
        const old = row.dataset.idx !== "" ? task.subs[+row.dataset.idx] : null;
        const sub = { ...(old || {}), title: st, start: ss || null, end: ss ? se || ss : null };
        if (ss) sub.dateText = "";
        if (!sub.id) sub.id = `${id}~${Date.now().toString(36)}${subs.length}`;
        subs.push(sub);
      }
      const data = { ...(task || {}), title, dept, start: dated ? v.start : null, end: dated ? v.end || v.start : null, owner: v.owner.trim(), memo: v.memo.trim(),
        dateText: dated ? "" : (task && task.dateText) || "", subs };
      // 날짜 미정 업무는 보고 있는 달(이미 미정이던 업무는 원래 달)의 '날짜 미정 · 상시 업무'에 표시
      if (!dated) data.months = task && !task.start && task.months && task.months.length ? task.months : [S.month];
      if (!task) { data.src = "manual"; data.by = userName(); }
      // 업무와 날짜가 다른 세부항목만 달력에 따로 표시
      data.subs.forEach((s) => { s.own = !!s.start && (s.start !== data.start || (s.end || s.start) !== data.end); });
      busy(f, true);
      try {
        await saveItem("task", data, id);
        rememberDept(dept); store("myDept", dept);
        closeModal(); toast(task ? "업무를 수정했습니다." : dated ? "업무를 추가했습니다." : "날짜 미정 업무로 추가했습니다.");
        if (!task && dated && !v.start.startsWith(S.month)) setMonth(v.start.slice(0, 7), v.start);
      } catch (e) { console.error(e); toast("저장하지 못했습니다."); busy(f, false); }
    };
    if (task) wireDelete(card, async () => {
      try { await deleteItem(task.id); closeModal(); toast("업무를 삭제했습니다."); } catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
    });
  });
}

function vacForm(vac, date) {
  if (!requireName()) return;
  const v = vac || { name: userName(), dept: "", start: date || S.sel, end: "", type: "연차", memo: "" };
  openModal(`<form class="form" id="vacForm">
    <h2>${vac ? "휴가 수정" : "휴가 등록"}</h2>
    <div class="row2">
      <label>이름 *<input name="name" value="${esc(v.name)}" required maxlength="20"></label>
      <label>부서<input name="dept" data-dept-combo autocomplete="off" value="${esc(v.dept || "")}" maxlength="30"></label>
    </div>
    <div class="row2">
      <label>시작일 *<input type="date" name="start" value="${esc(v.start || "")}" required></label>
      <label>종료일 <small>(하루면 비워두기)</small><input type="date" name="end" value="${esc(v.end && v.end !== v.start ? v.end : "")}"></label>
    </div>
    <label>종류<select name="type">${VAC_TYPES.map((t) => `<option ${t === v.type ? "selected" : ""}>${t}</option>`).join("")}</select></label>
    <label>메모<input name="memo" value="${esc(v.memo || "")}" maxlength="100" placeholder="예: 업무 대행 홍길동"></label>
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
// ───────── 공지 ─────────
// 게시 기간에 걸친 달마다 공지 칸에 표시. 엑셀 공지는 기간 없이 업로드한 달에만 표시
function noteForm(note) {
  if (!requireName()) return;
  const n = note || { dept: "", text: "", start: S.month + "-01", end: "" };
  openModal(`<form class="form" id="noteForm">
    <h2>${note ? "공지 수정" : "📢 공지 등록"}</h2>
    <label>내용 *<textarea name="text" rows="3" required maxlength="500">${esc(n.text)}</textarea></label>
    <label>부서<input name="dept" data-dept-combo autocomplete="off" value="${esc(n.dept || "")}" maxlength="30" placeholder="비우면 전체 공지"></label>
    <div class="row2">
      <label>게시 시작일<input type="date" name="start" value="${esc(n.start || "")}"></label>
      <label>게시 종료일 <small>(비우면 그 달만)</small><input type="date" name="end" value="${esc(n.end && n.end !== n.start ? n.end : "")}"></label>
    </div>
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">저장</button></div>
    ${note ? deleteRow("공지") : ""}
  </form>`, (card) => {
    const f = $("#noteForm", card);
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const x = Object.fromEntries(new FormData(f));
      const text = x.text.trim();
      if (!text) return;
      if (x.start && x.end && x.end < x.start) { toast("종료일이 시작일보다 빠릅니다."); return; }
      const start = isISO(x.start) ? x.start : "";
      const data = { ...(note || {}), text, dept: x.dept.trim(), start, end: start ? x.end || start : "", src: note ? note.src || "manual" : "manual", by: note ? note.by || "" : userName() };
      busy(f, true);
      try {
        await saveItem("note", data, note && note.id);
        rememberDept(data.dept);
        closeModal(); toast(note ? "공지를 수정했습니다." : "공지를 등록했습니다.");
        if (!note && start && !start.startsWith(S.month)) setMonth(start.slice(0, 7));
      } catch (e) { console.error(e); toast("저장하지 못했습니다."); busy(f, false); }
    };
    if (note) wireDelete(card, async () => {
      try { await deleteItem(note.id); closeModal(); toast("공지를 삭제했습니다."); } catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
    });
  });
}

// ───────── 개인 일정 ─────────
function pwFields(exists) {
  return exists
    ? `<label>개인 비밀번호<input type="password" name="ppw" autocomplete="off" required></label>`
    : `<p class="hint">처음 사용하는 이름입니다. <b>개인 비밀번호</b>를 정해 주세요. 잊어버리면 비공개 기록을 다시 볼 수 없습니다.</p>
       <div class="row2"><label>개인 비밀번호 (4자 이상)<input type="password" name="ppw" minlength="4" autocomplete="new-password" required></label>
       <label>한 번 더 입력<input type="password" name="ppw2" minlength="4" autocomplete="new-password" required></label></div>`;
}
async function tryUnlockFromForm(f) {
  const pw = f.ppw.value;
  if (f.ppw2 && pw !== f.ppw2.value) { toast("두 비밀번호가 다릅니다."); return false; }
  const r = await unlockPersonal(userName(), pw, f.premember ? f.premember.checked : false);
  if (r === "wrong") { toast("개인 비밀번호가 맞지 않습니다."); f.ppw.select(); return false; }
  return true;
}

async function unlockForm() {
  if (!requireName()) return;
  if (P.key) { lockPersonal(); toast("비공개 기록을 잠갔습니다."); return; }
  const name = userName();
  const exists = await hasProfile(name);
  openModal(`<form class="form" id="pUnlock">
    <h2>🔒 ${esc(name)}님의 비공개 기록</h2>
    <p class="hint">개인 비밀번호로 잠긴 기록은 본인만 볼 수 있습니다. 사이트 관리자도 내용을 볼 수 없습니다.</p>
    ${pwFields(exists)}
    <label class="switch"><input type="checkbox" name="premember"><span>이 기기에서 기억하기 (공용 PC에서는 끄세요)</span></label>
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">${exists ? "열기" : "비밀번호 정하고 열기"}</button></div>
  </form>`, (card) => {
    const f = $("#pUnlock", card);
    f.onsubmit = async (ev) => {
      ev.preventDefault(); busy(f, true);
      try { if (await tryUnlockFromForm(f)) { closeModal(); toast("비공개 기록이 열렸습니다."); } }
      catch (e) { console.error(e); toast("확인하지 못했습니다."); }
      busy(f, false);
    };
  });
}

async function personalForm(item, date) {
  if (!requireName()) return;
  if (item && !isMine(item)) { toast("본인 기록만 수정할 수 있습니다."); return; }
  const p = item || { title: "", start: date || S.sel, end: "", memo: "", private: false };
  const needPw = !P.key;
  const exists = needPw ? await hasProfile(userName()) : true;
  openModal(`<form class="form" id="pForm">
    <h2>${item ? "개인 업무 기록 수정" : "📝 개인 업무 기록"} <small class="muted">· ${esc(userName())}</small></h2>
    <label>업무 내용 *<textarea name="title" rows="2" required maxlength="300">${esc(p.title)}</textarea></label>
    <div class="row2">
      <label>날짜(시작) *<input type="date" name="start" value="${esc(p.start || "")}" required></label>
      <label>종료일 <small>(하루면 비워두기)</small><input type="date" name="end" value="${esc(p.end && p.end !== p.start ? p.end : "")}"></label>
    </div>
    <label>메모<input name="memo" value="${esc(p.memo || "")}" maxlength="200"></label>
    <label class="switch priv-switch"><input type="checkbox" name="priv" ${p.private ? "checked" : ""}><span>🔒 <b>나만 보기</b> — 개인 비밀번호로 잠가서 다른 사람에게 보이지 않게 합니다</span></label>
    <div id="pPwBox" hidden>${needPw ? pwFields(exists) + `<label class="switch"><input type="checkbox" name="premember"><span>이 기기에서 개인 비밀번호 기억하기</span></label>` : ""}</div>
    <div class="form-actions"><button type="button" class="btn" data-close>취소</button><button class="btn primary" type="submit">저장</button></div>
    ${item ? deleteRow("기록") : ""}
  </form>`, (card) => {
    const f = $("#pForm", card);
    const box = $("#pPwBox", card);
    const sync = () => {
      const show = f.priv.checked && needPw;
      box.hidden = !show;
      $$("input[type=password]", box).forEach((i) => { i.required = show; });
    };
    f.priv.onchange = sync; sync();
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const v = Object.fromEntries(new FormData(f));
      const title = v.title.trim();
      if (!title || !isISO(v.start)) return;
      if (v.end && v.end < v.start) { toast("종료일이 시작일보다 빠릅니다."); return; }
      busy(f, true);
      try {
        if (f.priv.checked && !P.key && !(await tryUnlockFromForm(f))) { busy(f, false); return; }
        const data = { ...(item || {}), name: userName(), dept: (item && item.dept) || store("myDept") || "", title, start: v.start, end: v.end || v.start,
          memo: v.memo.trim(), done: item ? !!item.done : false, private: f.priv.checked };
        await savePersonal(data, item && item.id);
        closeModal(); toast(item ? "기록을 수정했습니다." : f.priv.checked ? "🔒 비공개 기록을 추가했습니다." : "개인 업무 기록을 추가했습니다.");
        if (!item && !v.start.startsWith(S.month)) setMonth(v.start.slice(0, 7), v.start);
      } catch (e) { console.error(e); toast("저장하지 못했습니다."); busy(f, false); }
    };
    if (item) wireDelete(card, async () => {
      try { await deleteItem(item.id); closeModal(); toast("기록을 삭제했습니다."); } catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
    });
  });
}

async function togglePersonal(id, done) {
  const copies = [S.personal, S.allPersonal || []].map((l) => l.find((x) => x.id === id)).filter(Boolean);
  const p = copies[0];
  if (!p) return;
  if (!isMine(p)) { toast("본인 기록만 체크할 수 있습니다."); render(); return; }
  const prev = p.done;
  const set = (v) => copies.forEach((c) => { c.done = v; c.doneAt = v ? Date.now() : null; });
  set(done); render();
  try { await savePersonal(p, p.id); }
  catch (e) { console.error(e); set(prev); render(); toast("저장하지 못했습니다."); }
}

async function addMember(form) {
  const name = form.name.value.trim();
  if (!name) return;
  if (!requireName()) return;
  if (people().some((p) => p.name === name)) { toast(`${name}님은 이미 목록에 있습니다.`); form.name.select(); return; }
  busy(form, true);
  try {
    await saveItem("member", { name, by: userName(), months: ["member"] });
    S.hidePeople.delete(name); savePeopleFilter();
    form.name.value = "";
    toast(`${name}님을 추가했습니다.`);
  } catch (e) { console.error(e); toast("추가하지 못했습니다."); }
  busy(form, false);
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
      parent = { dept, title: stripNum(t), start: d.start, end: d.end, dateText: d.start ? "" : d.raw, due: due.start || "", dueText: due.start ? "" : due.raw, memo, owner, subs: [] };
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

// ───────── 엑셀 다운로드 ─────────
// 지금 보고 있는 달의 업무·휴가. 업로드 양식과 같은 열 순서라 그대로 다시 올릴 수 있음 (개인 일정은 제외)
function downloadMonth() {
  if (!S.loaded) { toast("아직 불러오는 중입니다. 잠시 후 다시 눌러 주세요."); return; }
  ensureXLSX().then(() => {
    const doneCols = (id) => {
      const c = id && S.checks[id];
      if (!c || !c.done) return ["", "", ""];
      const t = new Date(c.at);
      return ["완료", c.by || "", `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())} ${pad(t.getHours())}:${pad(t.getMinutes())}`];
    };
    const aoa = [["일자", "종료일", "담당부서", "업무내용", "담당자", "비고", "완료여부", "완료자", "완료시각"]];
    S.tasks.forEach((t) => {
      aoa.push([t.start || t.dateText || "", t.end && t.end !== t.start ? t.end : "", t.dept || "", stripNum(t.title), t.owner || "", t.memo || "", ...doneCols(t.id)]);
      (t.subs || []).forEach((s) => {
        aoa.push([s.start || s.dateText || "", s.end && s.end !== s.start ? s.end : "", t.dept || "", "- " + s.title, "", s.memo || "", ...doneCols(s.own && s.id)]);
      });
    });
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws["!cols"] = [{ wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 48 }, { wch: 10 }, { wch: 16 }, { wch: 8 }, { wch: 10 }, { wch: 16 }];
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "업무계획");
    if (S.vacs.length) {
      const vs = XLSX.utils.aoa_to_sheet([["이름", "부서", "시작일", "종료일", "종류", "메모"],
        ...S.vacs.map((v) => [v.name || "", v.dept || "", v.start || "", v.end && v.end !== v.start ? v.end : "", v.type || "", v.memo || ""])]);
      vs["!cols"] = [{ wch: 10 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 8 }, { wch: 24 }];
      XLSX.utils.book_append_sheet(wb, vs, "휴가");
    }
    if (S.notes.length) {
      const ns = XLSX.utils.aoa_to_sheet([["부서", "공지 내용", "게시 시작일", "게시 종료일", "등록자"],
        ...S.notes.map((n) => [n.dept || "", n.text || "", n.start || "", n.end && n.end !== n.start ? n.end : "", n.by || (n.src === "excel" ? "엑셀" : "")])]);
      ns["!cols"] = [{ wch: 12 }, { wch: 60 }, { wch: 12 }, { wch: 12 }, { wch: 10 }];
      XLSX.utils.book_append_sheet(wb, ns, "공지");
    }
    XLSX.writeFile(wb, `업무계획_${S.month}.xlsx`);
  }).catch(() => toast("엑셀 파일을 만들지 못했습니다. 인터넷 연결을 확인해 주세요."));
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
      (await readDocs(snap.docs)).forEach((x) => { if ((x.kind === "task" || x.kind === "note") && x.src === "excel") existing.push(x); });
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
  let nameTimer;
  nameInput.addEventListener("input", () => {
    store("userName", nameInput.value.trim()); $(".who").classList.remove("need");
    if (P.key && P.name !== userName()) lockPersonal(); // 이름이 바뀌면 개인 잠금 해제 상태 해제
    clearTimeout(nameTimer); nameTimer = setTimeout(() => { autoUnlock(); render(); renderChat(); }, 600);
  });

  document.addEventListener("change", async (ev) => {
    const pe = ev.target.closest("input[data-person]");
    if (pe) { const n = pe.dataset.person; pe.checked ? S.hidePeople.delete(n) : S.hidePeople.add(n); savePeopleFilter(); render(); return; }
    if (ev.target.id === "allOpen") { S.allOpen = ev.target.checked; store("allOpen", S.allOpen ? "1" : "0"); render(); return; }
    if (ev.target.id === "allRange") { S.allRange = ev.target.value; store("allRange", S.allRange); render(); return; }
    const pc = ev.target.closest("input[data-pcheck]");
    if (pc) { if (!requireName()) { pc.checked = !pc.checked; return; } togglePersonal(pc.dataset.pcheck, pc.checked); return; }
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
    if ((el = t.closest("[data-add-task]"))) { taskForm(null, el.dataset.addTask || ""); return; }
    if ((el = t.closest("[data-add-vac]"))) { vacForm(null, el.dataset.addVac || S.sel); return; }
    if ((el = t.closest("[data-edit-note]"))) { noteForm(S.notes.find((x) => x.id === el.dataset.editNote)); return; }
    if (t.closest("[data-add-note]")) { noteForm(null); return; }
    if ((el = t.closest("[data-edit-personal]"))) { ev.preventDefault(); personalForm(S.personal.find((x) => x.id === el.dataset.editPersonal)); return; }
    if ((el = t.closest("[data-add-personal]"))) { personalForm(null, el.dataset.addPersonal || S.sel); return; }
    if (t.closest("#pLockBtn")) { unlockForm(); return; }
    if ((el = t.closest("[data-people]"))) {
      const mode = el.dataset.people, me = userName();
      S.hidePeople = new Set(mode === "all" ? [] : people().map((p) => p.name).filter((n) => mode === "none" || n !== me));
      savePeopleFilter(); render(); return;
    }
    if ((el = t.closest("[data-del-member]"))) {
      deleteItem(el.dataset.delMember).then(() => toast("목록에서 뺐습니다.")).catch((e) => { console.error(e); toast("삭제하지 못했습니다."); });
      return;
    }
    if ((el = t.closest("[data-go]"))) {
      const d = el.dataset.go;
      if (d.slice(0, 7) !== S.month) setMonth(d.slice(0, 7), d); else { S.sel = d; render(); }
      $("#dayPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }
    if (t.closest("#uploadBtn")) { uploadForm(); return; }
    if (t.closest("#downloadBtn")) { downloadMonth(); return; }
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
  document.addEventListener("submit", (ev) => { if (ev.target.id === "memberForm") { ev.preventDefault(); addMember(ev.target); } });

  $("#hideDone").addEventListener("change", (e) => { S.hideDone = e.target.checked; store("hideDone", S.hideDone ? "1" : "0"); render(); });
  $("#showVac").addEventListener("change", (e) => { S.showVac = e.target.checked; store("showVac", S.showVac ? "1" : "0"); render(); });
  $("#prevMonth").addEventListener("click", () => shiftMonth(-1));
  $("#nextMonth").addEventListener("click", () => shiftMonth(1));
  $("#todayBtn").addEventListener("click", () => setMonth(TODAY.slice(0, 7), TODAY));
}

// ───────── 팀 채팅 ─────────
// 메시지는 items 컬렉션에 kind: chat, months: ["chat-YYYY-MM"] 으로 암호화 저장. 이번 달은 실시간, 지난달은 버튼으로 불러옴
const chatKey = (ym) => "chat-" + ym;
const prevYM = (ym) => { let [y, m] = ym.split("-").map(Number); m--; if (m < 1) { m = 12; y--; } return `${y}-${pad(m)}`; };
const CH = { now: [], older: [], olderFrom: null, loaded: false, stick: true };
function subscribeChat() {
  db.collection("items").where("months", "array-contains", chatKey(TODAY.slice(0, 7))).onSnapshot(async (snap) => {
    CH.now = (await readDocs(snap.docs)).filter((x) => x.kind === "chat" && x.text);
    CH.loaded = true; renderChat();
  }, (e) => { console.error(e); $("#chatList").innerHTML = '<div class="empty">채팅을 불러오지 못했습니다. 새로고침 해주세요.</div>'; });
}
async function loadOlderChat(btn) {
  const ym = prevYM(CH.olderFrom || TODAY.slice(0, 7));
  btn.disabled = true; btn.textContent = "불러오는 중…";
  try {
    const snap = await db.collection("items").where("months", "array-contains", chatKey(ym)).get();
    const list = (await readDocs(snap.docs)).filter((x) => x.kind === "chat" && x.text);
    CH.older = [...list, ...CH.older]; CH.olderFrom = ym;
    const box = $("#chatList"), h = box.scrollHeight;
    CH.stick = false; renderChat();
    box.scrollTop = box.scrollHeight - h; // 보던 위치 유지
    if (!list.length) toast(`${+ym.slice(5)}월에는 대화가 없습니다.`);
  } catch (e) { console.error(e); toast("이전 대화를 불러오지 못했습니다."); btn.disabled = false; btn.textContent = "이전 달 대화 보기"; }
}
const hm = (ts) => { const d = new Date(ts), h = d.getHours(); return `${h < 12 ? "오전" : "오후"} ${h % 12 || 12}:${pad(d.getMinutes())}`; };
function renderChat() {
  const box = $("#chatList");
  if (!box || !CH.loaded) return;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const me = userName();
  const all = [...CH.older, ...CH.now].sort((a, b) => (a.ts || 0) - (b.ts || 0));
  const olderLabel = CH.olderFrom ? `${+prevYM(CH.olderFrom).slice(5)}월 대화 보기` : "이전 달 대화 보기";
  let html = `<button class="chat-more" data-chat-older>${olderLabel}</button>`, lastDay = "";
  all.forEach((m) => {
    const d = new Date(m.ts), day = `${d.getMonth() + 1}월 ${d.getDate()}일 (${WEEK[d.getDay()]})`;
    if (day !== lastDay) { html += `<div class="chat-day">${day}</div>`; lastDay = day; }
    const mine = !!me && m.name === me;
    // 보낸 사람 이름은 모든 메시지에 표시 (내 메시지 포함)
    html += `<div class="msg ${mine ? "mine" : ""}" style="--c:${personColor(m.name)}">
      <div class="msg-name"><span class="av">${esc(initial(m.name))}</span>${esc(m.name)}${mine ? ' <small class="msg-me">(나)</small>' : ""}</div>
      <div class="msg-row"><div class="bubble">${esc(m.text)}</div><span class="msg-time">${hm(m.ts)}</span>${mine ? `<button class="msg-del" data-chat-del="${esc(m.id)}" title="삭제" aria-label="메시지 삭제">✕</button>` : ""}</div></div>`;
  });
  if (!all.length) html += '<div class="empty">아직 대화가 없습니다. 첫 메시지를 남겨 보세요.</div>';
  box.innerHTML = html;
  if (CH.stick || atBottom) box.scrollTop = box.scrollHeight;
  CH.stick = false;
}
async function sendChat() {
  const t = $("#chatText"), text = t.value.trim();
  if (!text) return;
  if (!requireName()) return;
  if (!db) { toast("서버에 연결되지 않았습니다."); return; }
  const form = $("#chatForm");
  busy(form, true);
  try {
    await saveItem("chat", { name: userName(), text, ts: Date.now(), months: [chatKey(TODAY.slice(0, 7))] });
    t.value = ""; t.style.height = ""; CH.stick = true; renderChat();
  } catch (e) { console.error(e); toast("메시지를 보내지 못했습니다."); }
  busy(form, false); t.focus();
}
function wireChat() {
  const t = $("#chatText");
  $("#chatForm").addEventListener("submit", (ev) => { ev.preventDefault(); sendChat(); });
  t.addEventListener("keydown", (ev) => { if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); sendChat(); } });
  t.addEventListener("input", () => { t.style.height = ""; t.style.height = Math.min(t.scrollHeight + 2, 120) + "px"; });
  $("#chatList").addEventListener("click", async (ev) => {
    const older = ev.target.closest("[data-chat-older]");
    if (older) { loadOlderChat(older); return; }
    const del = ev.target.closest("[data-chat-del]");
    if (!del) return;
    if (!del.classList.contains("armed")) { // 한 번 더 눌러야 삭제
      del.classList.add("armed"); del.textContent = "삭제";
      setTimeout(() => { if (del.isConnected) { del.classList.remove("armed"); del.textContent = "✕"; } }, 3000);
      return;
    }
    try { await deleteItem(del.dataset.chatDel); CH.older = CH.older.filter((m) => m.id !== del.dataset.chatDel); renderChat(); }
    catch (e) { console.error(e); toast("삭제하지 못했습니다."); }
  });
}

// ───────── 시작 ─────────
async function boot() {
  wireEvents();
  wireChat();
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
  subscribeGlobal();
  subscribeChat();
  autoUnlock();
}

// 이 기기에 기억된 개인 비밀번호가 있으면 자동으로 열기
async function autoUnlock() {
  const name = userName();
  if (!db || !name || P.key) return;
  const pw = store("pPw:" + name);
  if (!pw) return;
  try { if ((await unlockPersonal(name, pw, true)) === "wrong") store("pPw:" + name, null); } catch (e) { console.error(e); }
}
