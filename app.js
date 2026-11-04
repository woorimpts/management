// ── 비밀번호 잠금 해제 ──
(function () {
  "use strict";
  const lock = document.getElementById("lock");
  const form = document.getElementById("lockForm");
  const input = document.getElementById("lockPw");
  const msg = document.getElementById("lockMsg");
  const KEY = "sitePw";
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function decrypt(pw) {
    const e = window.PLANS_ENC;
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(e.salt), iterations: e.iter, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(e.iv) }, key, b64(e.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function tryOpen(pw, remember) {
    try {
      const plans = await decrypt(pw);
      try { if (remember) localStorage.setItem(KEY, pw); } catch (e) {}
      lock.hidden = true;
      document.body.classList.remove("locked");
      window.bootApp(plans);
      return true;
    } catch (e) { return false; }
  }

  if (!window.PLANS_ENC) { lock.hidden = true; document.body.classList.remove("locked"); window.bootApp(window.PLANS || {}); return; }
  if (!window.crypto || !crypto.subtle) { lock.classList.add("ready"); msg.textContent = "이 브라우저는 지원되지 않습니다. 크롬·엣지 최신 버전으로 접속해 주세요."; return; }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "확인 중…";
    const ok = await tryOpen(input.value, document.getElementById("lockRemember").checked);
    if (!ok) { msg.textContent = "비밀번호가 맞지 않습니다."; input.select(); }
  });

  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  (saved ? tryOpen(saved, true) : Promise.resolve(false)).then((ok) => {
    if (!ok) { try { localStorage.removeItem(KEY); } catch (e) {} lock.classList.add("ready"); input.focus(); }
  });
})();

function bootApp(PLANS) {
  "use strict";

  const MONTHS = Object.keys(PLANS).sort();
  const WEEK = ["일", "월", "화", "수", "목", "금", "토"];
  const FIREBASE_VER = "10.12.2";

  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const pad = (n) => String(n).padStart(2, "0");
  const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const TODAY = iso(new Date());
  const md = (s) => { const [, m, d] = s.split("-"); return `${+m}/${+d}`; };
  const mdw = (s) => `${md(s)}(${WEEK[new Date(s + "T00:00").getDay()]})`;
  const period = (a, b) => (!a ? "" : a === b ? mdw(a) : `${mdw(a)} ~ ${mdw(b)}`);
  const stripNum = (t) => t.replace(/^\d+\s*\.\s*/, "");

  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { return null; }
  }

  // ── 부서 색상 ──
  const DEPTS = [];
  MONTHS.forEach((m) => PLANS[m].tasks.forEach((t) => { if (!DEPTS.includes(t.dept)) DEPTS.push(t.dept); }));
  const color = (dept) => `var(--d${Math.max(0, DEPTS.indexOf(dept)) % 6})`;
  const shortDept = (d) => (d.match(/\((.+)\)/) || [, d])[1];

  // ── 상태 ──
  const state = {
    month: MONTHS.includes(TODAY.slice(0, 7)) ? TODAY.slice(0, 7) : (MONTHS.filter((m) => m <= TODAY.slice(0, 7)).pop() || MONTHS[0]),
    checks: {},
    dept: store("dept") || "all",
    hideDone: store("hideDone") === "1",
    view: store("view") || "calendar",
    sel: null,
  };
  if (state.dept !== "all" && !DEPTS.includes(state.dept)) state.dept = "all";

  // ── 저장소: Firebase 또는 로컬 미리보기 ──
  const Backend = {
    mode: "local",
    unsub: null,
    db: null,
    async init() {
      const cfg = window.FIREBASE_CONFIG;
      if (!cfg || !cfg.projectId) { setSync("local", "미리보기 모드 (내 브라우저에만 저장)"); return; }
      try {
        await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VER}/firebase-app-compat.js`);
        await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VER}/firebase-firestore-compat.js`);
        firebase.initializeApp(cfg);
        this.db = firebase.firestore();
        this.mode = "firebase";
      } catch (e) {
        console.error(e);
        setSync("err", "서버 연결 실패 — 미리보기 모드");
      }
    },
    subscribe(month, cb) {
      if (this.unsub) { this.unsub(); this.unsub = null; }
      if (this.mode === "local") {
        let data = {};
        try { data = JSON.parse(store("checks_" + month) || "{}"); } catch (e) {}
        cb(data);
        return;
      }
      setSync("", "연결 중…");
      this.unsub = this.db.collection("checks").where("month", "==", month).onSnapshot(
        (snap) => {
          const data = {};
          snap.forEach((doc) => {
            const v = doc.data();
            data[v.item] = { done: !!v.done, by: v.by || "", at: v.at && v.at.toMillis ? v.at.toMillis() : Date.now() };
          });
          setSync("live", "실시간 공유 중");
          cb(data);
        },
        (err) => { console.error(err); setSync("err", "권한/연결 오류 — 설정가이드 4단계 확인"); }
      );
    },
    async set(month, item, done, by) {
      if (this.mode === "local") {
        const data = { ...state.checks, [item]: { done, by, at: Date.now() } };
        store("checks_" + month, JSON.stringify(data));
        return;
      }
      await this.db.collection("checks").doc(`${month}_${item}`).set({
        month, item, done, by, at: firebase.firestore.FieldValue.serverTimestamp(),
      });
    },
  };

  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement("script");
      s.src = src; s.onload = res; s.onerror = () => rej(new Error("load fail " + src));
      document.head.appendChild(s);
    });
  }
  function setSync(cls, text) {
    const el = $("#syncStatus");
    el.className = "sync " + cls;
    el.querySelector("b").textContent = text;
  }

  // ── 데이터 가공 ──
  const plan = () => PLANS[state.month];
  const isDone = (id) => !!(state.checks[id] && state.checks[id].done);
  const deptOk = (d) => state.dept === "all" || state.dept === d;

  /** 달력에 올라가는 항목: 상위 업무 + 날짜가 다른 세부 업무 */
  function entries() {
    const out = [];
    plan().tasks.forEach((t) => {
      if (t.start) out.push({ id: t.id, task: t, start: t.start, end: t.end, title: t.title });
      t.subs.forEach((s) => { if (s.own) out.push({ id: s.id, task: t, sub: s, start: s.start, end: s.end, title: s.title }); });
    });
    return out;
  }
  const isLate = (e) => !isDone(e.id) && e.end && e.end < TODAY;

  function checkables() {
    const out = [];
    plan().tasks.forEach((t) => {
      out.push({ id: t.id, dept: t.dept, end: t.end });
      t.subs.forEach((s) => { if (s.own) out.push({ id: s.id, dept: t.dept, end: s.end }); });
    });
    return out;
  }

  // ── 렌더링 ──
  function render() {
    if (!plan()) { $("#calendarView").innerHTML = '<p class="empty">data.js 에 업무 데이터가 없습니다.</p>'; return; }
    const [y, m] = state.month.split("-").map(Number);
    $("#planTitle").textContent = plan().title;
    document.title = plan().title;
    $("#monthLabel").textContent = `${y}년 ${m}월`;
    const idx = MONTHS.indexOf(state.month);
    $("#prevMonth").disabled = idx <= 0;
    $("#nextMonth").disabled = idx >= MONTHS.length - 1;
    $("#hideDone").checked = state.hideDone;
    document.querySelectorAll(".seg button").forEach((b) => b.classList.toggle("on", b.dataset.view === state.view));
    $("#calendarView").hidden = state.view !== "calendar";
    $("#listView").hidden = state.view !== "list";

    renderSummary();
    renderFilters();
    if (state.view === "calendar") { renderCalendar(); renderPanel(); } else renderList();
    renderExtra();
  }

  function renderSummary() {
    const items = checkables();
    const groups = [{ key: "all", name: "전체", c: "var(--text)" }].concat(
      DEPTS.filter((d) => items.some((i) => i.dept === d)).map((d) => ({ key: d, name: d, c: color(d) }))
    );
    $("#summary").innerHTML = groups.map((g) => {
      const list = g.key === "all" ? items : items.filter((i) => i.dept === g.key);
      const done = list.filter((i) => isDone(i.id)).length;
      const late = list.filter((i) => !isDone(i.id) && i.end && i.end < TODAY).length;
      const pct = list.length ? Math.round((done / list.length) * 100) : 0;
      return `<button class="stat ${state.dept === g.key ? "on" : ""}" data-dept="${esc(g.key)}" style="--c:${g.c}">
        <div class="name"><i></i>${esc(g.name)}</div>
        <div class="num">${pct}%<small>${done}/${list.length}</small></div>
        <div class="bar"><span style="width:${pct}%"></span></div>
        <div class="late">${late ? `기한 지남 ${late}건` : ""}</div>
      </button>`;
    }).join("");
  }

  function renderFilters() {
    const ds = DEPTS.filter((d) => plan().tasks.some((t) => t.dept === d));
    $("#deptFilters").innerHTML =
      `<button class="chip ${state.dept === "all" ? "on" : ""}" data-dept="all">전체</button>` +
      ds.map((d) => `<button class="chip ${state.dept === d ? "on" : ""}" data-dept="${esc(d)}" style="--c:${color(d)}"><i></i>${esc(d)}</button>`).join("");
  }

  function dayEntries(date) {
    return entries().filter((e) => e.start <= date && date <= e.end && deptOk(e.task.dept) && !(state.hideDone && isDone(e.id)));
  }

  function renderCalendar() {
    $("#calHead").innerHTML = WEEK.map((w) => `<div>${w}</div>`).join("");
    const [y, m] = state.month.split("-").map(Number);
    const first = new Date(y, m - 1, 1);
    const start = new Date(y, m - 1, 1 - first.getDay());
    const last = new Date(y, m, 0);
    const cells = Math.ceil((first.getDay() + last.getDate()) / 7) * 7;
    let html = "";
    for (let i = 0; i < cells; i++) {
      const d = new Date(start); d.setDate(start.getDate() + i);
      const ds = iso(d);
      const out = d.getMonth() !== m - 1;
      const cls = ["cell", out && "out", ds === TODAY && "today", ds === state.sel && "sel", d.getDay() === 0 && "sun", d.getDay() === 6 && "sat"].filter(Boolean).join(" ");
      if (out) { html += `<div class="${cls}"><div class="dhead"><span class="dnum">${d.getDate()}</span></div></div>`; continue; }
      const list = dayEntries(ds);
      const doneN = list.filter((e) => isDone(e.id)).length;
      const lateN = list.filter(isLate).length;
      const countCls = lateN ? "late" : list.length && doneN === list.length ? "all" : "";
      const count = list.length ? `<span class="dcount ${countCls}">${doneN}/${list.length}</span>` : "";
      const MAX = 4;
      const chips = list.slice(0, MAX).map((e) => {
        const done = isDone(e.id);
        return `<label class="task-chip ${done ? "done" : ""} ${isLate(e) ? "late" : ""}" style="--c:${color(e.task.dept)}" title="${esc(e.task.dept + " · " + (e.sub ? stripNum(e.task.title) + " › " : "") + e.title)}">
          <input type="checkbox" data-id="${e.id}" ${done ? "checked" : ""}><span>${esc(stripNum(e.title))}</span></label>`;
      }).join("");
      const more = list.length > MAX ? `<div class="more">+${list.length - MAX}건 더보기</div>` : "";
      const dots = `<div class="dots">${list.slice(0, 8).map((e) => `<i style="--c:${color(e.task.dept)}" class="${isDone(e.id) ? "done" : ""}"></i>`).join("")}</div>`;
      html += `<div class="${cls}" data-date="${ds}"><div class="dhead"><span class="dnum">${d.getDate()}</span>${count}</div>${chips}${more}${dots}</div>`;
    }
    $("#calGrid").innerHTML = html;
  }

  function checkInfo(id) {
    const c = state.checks[id];
    if (!c || !c.done) return "";
    const t = new Date(c.at);
    return `<span class="by">✓ ${esc(c.by || "?")} · ${t.getMonth() + 1}/${t.getDate()} ${pad(t.getHours())}:${pad(t.getMinutes())}</span>`;
  }

  function taskCard(t, opts = {}) {
    const done = isDone(t.id);
    const late = !done && t.end && t.end < TODAY;
    const meta = [
      `<span class="dept">${esc(t.dept)}</span>`,
      t.start ? `<span>📅 ${period(t.start, t.end)}</span>` : t.dateText ? `<span>📅 ${esc(t.dateText)}</span>` : "",
      t.due ? `<span>기한 ${mdw(t.due)}</span>` : t.dueText ? `<span>${esc(t.dueText)}</span>` : "",
      t.memo ? `<span>비고: ${esc(t.memo)}</span>` : "",
      late ? `<span class="late">기한 지남</span>` : "",
      checkInfo(t.id),
    ].join("");
    const subs = t.subs.length ? `<ul class="subs">${t.subs.map((s) => {
      if (!s.own) return `<li><span class="t">${esc(s.title)}${s.dateText ? ` (${esc(s.dateText)})` : ""}</span></li>`;
      const sd = isDone(s.id);
      return `<li class="chk ${sd ? "done" : ""}"><input type="checkbox" data-id="${s.id}" ${sd ? "checked" : ""}>
        <span><span class="t">${esc(s.title)}</span> <span class="sd">${period(s.start, s.end)}</span> ${checkInfo(s.id)}</span></li>`;
    }).join("")}</ul>` : "";
    return `<div class="task ${done ? "done" : ""}" style="--c:${color(t.dept)}">
      <label class="task-row"><input type="checkbox" data-id="${t.id}" ${done ? "checked" : ""}>
        <div><div class="task-title">${esc(t.title)}</div><div class="meta">${meta}</div></div></label>${subs}</div>`;
  }

  function subCard(e) {
    const s = e.sub, t = e.task, done = isDone(s.id);
    return `<div class="task ${done ? "done" : ""}" style="--c:${color(t.dept)}">
      <div class="parent-ref">${esc(t.title)} ›</div>
      <label class="task-row"><input type="checkbox" data-id="${s.id}" ${done ? "checked" : ""}>
        <div><div class="task-title">${esc(s.title)}</div>
        <div class="meta"><span class="dept">${esc(t.dept)}</span><span>📅 ${period(s.start, s.end)}</span>${isLate(e) ? '<span class="late">기한 지남</span>' : ""}${checkInfo(s.id)}</div></div></label></div>`;
  }

  function renderPanel() {
    const d = state.sel;
    const list = dayEntries(d);
    const doneN = list.filter((e) => isDone(e.id)).length;
    const [, m, day] = d.split("-");
    $("#dayPanel").innerHTML = `<div class="panel-head"><h2>${+m}월 ${+day}일 (${WEEK[new Date(d + "T00:00").getDay()]})${d === TODAY ? " · 오늘" : ""}</h2>
      <p>${list.length ? `업무 ${list.length}건 · 완료 ${doneN}건` : "날짜를 누르면 해당 일의 업무가 보입니다"}</p></div>
      <div class="panel-body">${list.length ? list.map((e) => (e.sub ? subCard(e) : taskCard(e.task))).join("") : '<div class="empty">이 날 마감인 업무가 없습니다.</div>'}</div>`;
  }

  function renderList() {
    const ds = DEPTS.filter((d) => deptOk(d) && plan().tasks.some((t) => t.dept === d));
    $("#listView").innerHTML = ds.map((d) => {
      const ts = plan().tasks.filter((t) => t.dept === d && !(state.hideDone && isDone(t.id)))
        .sort((a, b) => (a.start || "9") < (b.start || "9") ? -1 : (a.start || "9") > (b.start || "9") ? 1 : 0);
      const all = checkables().filter((i) => i.dept === d);
      const doneN = all.filter((i) => isDone(i.id)).length;
      return `<section class="group" style="--c:${color(d)}"><h3><i></i>${esc(d)}<small>${doneN}/${all.length} 완료</small></h3>
        <div class="body">${ts.map((t) => taskCard(t)).join("") || '<div class="empty">표시할 업무가 없습니다.</div>'}</div></section>`;
    }).join("");
  }

  function renderExtra() {
    const undated = plan().tasks.filter((t) => !t.start && deptOk(t.dept) && !(state.hideDone && isDone(t.id)));
    const notes = plan().notes.filter((n) => deptOk(n.dept));
    let html = "";
    if (state.view === "calendar" && undated.length)
      html += `<section class="group"><h3>날짜 미정 · 상시 업무<small>${undated.length}건</small></h3><div class="body">${undated.map((t) => taskCard(t)).join("")}</div></section>`;
    if (notes.length)
      html += `<section class="group"><h3>공지</h3><ul class="notes">${notes.map((n) => `<li><b style="color:${color(n.dept)}">${esc(shortDept(n.dept))}</b> ${esc(n.text)}</li>`).join("")}</ul></section>`;
    $("#extra").innerHTML = html;
  }

  // ── 토스트 ──
  let toastTimer;
  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg; el.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2400);
  }

  // ── 이벤트 ──
  const nameInput = $("#userName");
  nameInput.value = store("userName") || "";
  nameInput.addEventListener("input", () => { store("userName", nameInput.value.trim()); nameInput.parentElement.classList.remove("need"); });

  document.addEventListener("change", async (ev) => {
    const cb = ev.target.closest("input[data-id]");
    if (!cb) return;
    const id = cb.dataset.id;
    const name = nameInput.value.trim();
    if (!name) {
      cb.checked = !cb.checked;
      nameInput.parentElement.classList.add("need");
      nameInput.focus();
      toast("체크하기 전에 오른쪽 위에 이름을 입력해 주세요.");
      return;
    }
    const done = cb.checked;
    const prev = state.checks[id];
    state.checks = { ...state.checks, [id]: { done, by: name, at: Date.now() } };
    render();
    try {
      await Backend.set(state.month, id, done, name);
    } catch (e) {
      console.error(e);
      state.checks = { ...state.checks, [id]: prev };
      render();
      toast("저장하지 못했습니다. 인터넷 연결을 확인해 주세요.");
    }
  });

  document.addEventListener("click", (ev) => {
    const deptBtn = ev.target.closest("[data-dept]");
    if (deptBtn) {
      const d = deptBtn.dataset.dept;
      state.dept = state.dept === d && d !== "all" ? "all" : d;
      store("dept", state.dept); render(); return;
    }
    const viewBtn = ev.target.closest("[data-view]");
    if (viewBtn) { state.view = viewBtn.dataset.view; store("view", state.view); render(); return; }
    if (ev.target.closest(".task-chip")) {
      // 칩의 글자 부분을 눌렀을 땐 체크하지 않고 해당 날짜만 선택
      if (!ev.target.matches("input")) ev.preventDefault();
    }
    const cell = ev.target.closest(".cell[data-date]");
    if (cell && !ev.target.matches("input")) {
      state.sel = cell.dataset.date; render();
      if (window.innerWidth <= 1100) $("#dayPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });

  $("#hideDone").addEventListener("change", (e) => { state.hideDone = e.target.checked; store("hideDone", state.hideDone ? "1" : "0"); render(); });
  $("#prevMonth").addEventListener("click", () => goMonth(-1));
  $("#nextMonth").addEventListener("click", () => goMonth(1));
  $("#todayBtn").addEventListener("click", () => {
    const tm = TODAY.slice(0, 7);
    if (MONTHS.includes(tm)) { if (tm !== state.month) setMonth(tm); state.sel = TODAY; render(); }
    else toast("이번 달 업무계획이 아직 없습니다.");
  });

  function goMonth(step) {
    const i = MONTHS.indexOf(state.month) + step;
    if (i >= 0 && i < MONTHS.length) setMonth(MONTHS[i]);
  }
  function setMonth(m) {
    state.month = m;
    state.sel = TODAY.startsWith(m) ? TODAY : m + "-01";
    state.checks = {};
    render();
    Backend.subscribe(m, (data) => { state.checks = data; render(); });
  }

  // ── 시작 ──
  if (!MONTHS.length) { $("#calendarView").innerHTML = '<p class="empty">data.js 가 없습니다. tools/convert.py 를 실행하세요.</p>'; return; }
  Backend.init().then(() => setMonth(state.month));
}
