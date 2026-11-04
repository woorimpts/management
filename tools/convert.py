"""
엑셀 업무계획 → data.js 변환기

사용법 (업무달력 폴더에서):
    python tools/convert.py "../2026년 11월 부서업무계획.xlsx" "../2026년 12월 부서업무계획.xlsx" ...

- 여러 달 파일을 한꺼번에 넣으면 달력에서 월을 넘겨가며 볼 수 있습니다.
- 비밀번호는 .site-password 파일(또는 SITE_PASSWORD 환경변수)에서 읽어 data.js 를 암호화합니다.
- 파일 없이 실행하면 비밀번호만 바꿔서 다시 암호화합니다:  python tools/convert.py
- 이미 들어있는 달(plans.local.json)은 유지되고, 같은 달은 새 파일 내용으로 덮어씁니다.
- 업무 순서/문구가 바뀌면 그 업무의 체크 기록이 연결되지 않을 수 있으니,
  월 중간에 수정할 때는 업무를 맨 아래에 추가하는 방식을 권장합니다.
"""
import sys, re, json, datetime, collections, pathlib, os, base64, secrets

try:
    import openpyxl
except ImportError:
    sys.exit("openpyxl 이 필요합니다:  python -m pip install openpyxl")

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "data.js"
SRC = ROOT / "plans.local.json"        # 원본(평문) — GitHub 에 올라가지 않음
PW_FILE = ROOT / ".site-password"      # 사이트 비밀번호 — GitHub 에 올라가지 않음
ITER = 200_000

NUM_RE = re.compile(r"^\d+\s*\.")
RANGE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\s*~\s*(\d{1,2})$")

# 엑셀 '구 분' 값 → 표시할 부서 이름
DEPT_ALIASES = {
    "총괄": "총괄",
    "총무팀": "총무팀(인사)",   # '총무팀' 행 바로 아래가 (인사) 이므로 같은 그룹으로 묶음
    "(인사)": "총무팀(인사)",
    "(총무)": "총무팀(총무)",
    "재무팀": "재무팀",
}


def clean(s):
    return re.sub(r"\s+", " ", str(s).replace("\xa0", " ")).strip()


def parse_date(v):
    """반환: (start, end, raw) — 날짜를 못 읽으면 start=None"""
    if v is None:
        return None, None, ""
    if isinstance(v, datetime.datetime):
        d = v.date().isoformat()
        return d, d, d
    s = clean(v)
    m = RANGE_RE.match(s)
    if m:
        y, mo, d1, d2 = m.groups()
        return f"{y}-{mo}-{d1}", f"{y}-{mo}-{int(d2):02d}", s
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", s)
    if m:
        return s, s, s
    return None, None, "" if s == "-" else s


def convert(path):
    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb.worksheets[0]
    rows = [r for r in ws.iter_rows(values_only=True) if any(c is not None for c in r)]

    title = clean(rows[0][0]) if rows and rows[0][0] else pathlib.Path(path).stem
    tasks, notes = [], []
    dept, parent, child = None, None, None
    month_counter = collections.Counter()

    for r in rows[1:]:
        gubun, text, done_v, due_v, memo = (list(r) + [None] * 5)[:5]
        if gubun and clean(gubun).replace(" ", "") == "구분":
            continue  # 헤더
        if gubun:
            g = clean(gubun)
            dept = DEPT_ALIASES.get(g, g)
            parent, child = None, None
        if text is None:
            continue
        t = clean(text)
        if not t:
            continue
        start, end, raw = parse_date(done_v)
        due_start, _, due_raw = parse_date(due_v)
        if start:
            month_counter[start[:7]] += 1
        memo = clean(memo) if memo else ""

        # 날짜 없는 ※ 문장 = 부서 공지
        if t.startswith("※") and not start:
            notes.append({"dept": dept, "text": t})
            continue

        if NUM_RE.match(t) or parent is None:
            parent = {
                "id": f"{len(tasks) + 1:03d}",
                "dept": dept,
                "title": t,
                "start": start,
                "end": end,
                "dateText": raw if not start else "",
                "due": due_start or "",
                "dueText": due_raw if not due_start else "",
                "memo": memo,
                "subs": [],
            }
            tasks.append(parent)
            child = None
            continue

        # 하위 항목
        is_new_child = t[0] in "-※[" or child is None
        if not is_new_child:
            child["title"] += " " + t  # 이어지는 줄
            continue
        child = {
            "id": f"{parent['id']}-{len(parent['subs']) + 1:02d}",
            "title": t.lstrip("- ").strip() if t.startswith("-") else t,
            "start": start,
            "end": end,
            "dateText": raw if not start else "",
            "memo": memo,
        }
        parent["subs"].append(child)

    # 상위 업무에 날짜가 없으면 하위 항목 중 가장 늦은 날짜를 사용
    for p in tasks:
        if not p["start"]:
            ds = [s["end"] for s in p["subs"] if s["end"]]
            if ds:
                p["start"] = p["end"] = max(ds)
        for s in p["subs"]:
            # 상위와 같은 날짜면 굳이 달력에 따로 표시하지 않음
            s["own"] = bool(s["start"]) and (s["start"], s["end"]) != (p["start"], p["end"])

    month = month_counter.most_common(1)[0][0] if month_counter else datetime.date.today().strftime("%Y-%m")
    return month, {"title": title, "tasks": tasks, "notes": notes}


def load_existing():
    if SRC.exists():
        return json.loads(SRC.read_text(encoding="utf-8"))
    return {}


def get_password():
    pw = os.environ.get("SITE_PASSWORD")
    if not pw and PW_FILE.exists():
        pw = PW_FILE.read_text(encoding="utf-8").strip()
    if not pw:
        sys.exit("비밀번호가 없습니다. 업무달력 폴더에 .site-password 파일을 만들고 비밀번호를 한 줄로 적어주세요.")
    return pw


def encrypt(plans, pw):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, json.dumps(plans, ensure_ascii=False).encode("utf-8"), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}


def main():
    files = sys.argv[1:]
    plans = load_existing()
    if not files and not plans:
        sys.exit(__doc__)
    for f in files:
        month, plan = convert(f)
        plans[month] = plan
        n = len(plan["tasks"]) + sum(len(t["subs"]) for t in plan["tasks"])
        print(f"{month}: {plan['title']} — 업무 {len(plan['tasks'])}건 (세부 포함 {n}건)")
    plans = dict(sorted(plans.items()))
    SRC.write_text(json.dumps(plans, ensure_ascii=False, indent=1), encoding="utf-8")
    enc = encrypt(plans, get_password())
    OUT.write_text(
        "// 자동 생성 파일입니다(암호화됨). 직접 고치지 말고 tools/convert.py 로 다시 만드세요.\n"
        "window.PLANS_ENC = " + json.dumps(enc) + ";\n",
        encoding="utf-8",
    )
    print(f"저장(암호화): {OUT}  — 포함된 달: {', '.join(plans)}")


if __name__ == "__main__":
    main()
