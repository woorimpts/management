"""
사이트 비밀번호 설정 → lock.js 생성

사용법 (업무달력 폴더에서):
    python tools/set_password.py            # .site-password 파일의 비밀번호 사용
    python tools/set_password.py 새비밀번호   # 지정한 비밀번호 사용(.site-password 도 갱신)

주의: 업무·휴가·체크 기록은 이 비밀번호로 암호화되어 저장됩니다.
      비밀번호를 바꾸면 기존에 저장된 기록을 읽을 수 없게 되므로,
      운영 중에는 바꾸지 마세요. (바꿔야 하면 Claude에게 '데이터 옮기면서 비밀번호 변경' 요청)
"""
import sys, json, base64, secrets, pathlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = pathlib.Path(__file__).resolve().parent.parent
PW_FILE = ROOT / ".site-password"
OUT = ROOT / "lock.js"
ITER = 200_000
VERIFY_TEXT = "upmu-calendar-ok"


def main():
    if len(sys.argv) > 1:
        pw = sys.argv[1]
        PW_FILE.write_text(pw, encoding="utf-8")
    else:
        pw = PW_FILE.read_text(encoding="utf-8").strip()
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, VERIFY_TEXT.encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    lock = {"v": 2, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}
    OUT.write_text("// 자동 생성 파일 — tools/set_password.py\nwindow.LOCK = " + json.dumps(lock) + ";\n", encoding="utf-8")
    print(f"저장: {OUT}")


if __name__ == "__main__":
    main()
