import os, json, hashlib, shutil, subprocess, socket

KEY_DIR = "./keys"
KEY_REPO = "https://github.com/Idonot-Grief/httpc-keys.git"

HOST = "127.0.0.1"
HTTPC_PORT = 228
HTTP_PORT = 80

os.makedirs(KEY_DIR, exist_ok=True)

TEMP_KEY = None
USES = 0
MAX_USES = 5
PUB_SEED = None

# ---------------- KEY SYNC ----------------
def sync_keys():
    tmp = KEY_DIR + "_tmp"
    shutil.rmtree(tmp, ignore_errors=True)

    subprocess.run(
        ["git", "clone", "--depth", "1", KEY_REPO, tmp],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if not os.path.exists(tmp):
        return

    for f in os.listdir(tmp):
        if f.endswith(".cat"):
            shutil.copyfile(os.path.join(tmp, f), os.path.join(KEY_DIR, f))

    shutil.rmtree(tmp, ignore_errors=True)

# ---------------- CRYPTO ----------------
def stream(seed):
    h = hashlib.sha256(seed.encode()).digest()
    while True:
        for b in h:
            yield b
        h = hashlib.sha256(h).digest()

def crypt(data, seed):
    g = stream(seed)
    return bytes(b ^ next(g) for b in data)

# ---------------- CERTS ----------------
def ids():
    out = []
    for f in os.listdir(KEY_DIR):
        if f.endswith(".cat"):
            with open(os.path.join(KEY_DIR, f), "r", encoding="utf-8-sig") as fh:
                out.append(json.load(fh)["id"])
    return out

def seed(cid):
    with open(os.path.join(KEY_DIR, cid + ".cat"), "r", encoding="utf-8-sig") as fh:
        return json.load(fh)["seed"]

# ---------------- HTTP FALLBACK ----------------
def plain_http():
    with socket.create_connection((HOST, HTTP_PORT)) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        return s.recv(65535)

# ---------------- REQUEST ----------------
def request(payload):
    global TEMP_KEY, USES, PUB_SEED

    try:
        with socket.create_connection((HOST, HTTPC_PORT), timeout=1) as s:
            if b"HTTPC-HELLO" not in s.recv(1024):
                raise Exception

            s.sendall(",".join(ids()).encode() + b"\n")
            r = s.recv(1024)

            if b"HTTPC-FALLBACK" in r:
                raise Exception

            cid = r.decode().split(":")[1].strip()
            PUB_SEED = seed(cid)

            if TEMP_KEY is None or USES >= MAX_USES:
                info = json.loads(crypt(s.recv(4096), PUB_SEED))
                TEMP_KEY = info["temp_key"]
                USES = 0
                return request(payload)

            USES += 1
            s.sendall(crypt(crypt(payload, TEMP_KEY), PUB_SEED))
            return crypt(crypt(s.recv(65535), PUB_SEED), TEMP_KEY)

    except:
        return plain_http()

# ---------------- RUN ----------------
if __name__ == "__main__":
    sync_keys()
    for i in range(10):
        print(request(b"GET / HTTP/1.1\r\nHost:x\r\n\r\n").decode(errors="ignore"))
