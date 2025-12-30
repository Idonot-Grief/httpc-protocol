import os, json, hashlib, random, shutil, subprocess, threading, time, socket

# ---------------- CONFIG ----------------
CERT_DIR = "./cert"
KEY_REPO = "https://github.com/Idonot-Grief/httpc-keys.git"
SYNC_INTERVAL = 3 * 3600
TEMP_KEY_USES = 5

HTTPC_PORT = 228
HTTP_PORT = 80

os.makedirs(CERT_DIR, exist_ok=True)

clients = {}  # ip -> state

# ---------------- KEY SYNC ----------------
def sync_keys():
    tmp = CERT_DIR + "_tmp"
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
            shutil.copyfile(os.path.join(tmp, f), os.path.join(CERT_DIR, f))

    shutil.rmtree(tmp, ignore_errors=True)

def periodic_sync():
    while True:
        sync_keys()
        time.sleep(SYNC_INTERVAL)

threading.Thread(target=periodic_sync, daemon=True).start()

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
def load_certs():
    out = {}
    for f in os.listdir(CERT_DIR):
        if f.endswith(".cat"):
            path = os.path.join(CERT_DIR, f)
            with open(path, "r", encoding="utf-8-sig") as fh:
                j = json.load(fh)
                out[j["id"]] = j["seed"]
    return out

# ---------------- HTTP ----------------
def http_response(body=b"Hello (HTTP fallback)"):
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Content-Type: text/plain\r\n\r\n" + body
    )

# ---------------- HTTPC ----------------
def handle_httpc(conn, addr):
    ip = addr[0]
    certs = load_certs()

    conn.sendall(b"HTTPC-HELLO\n")
    ids = conn.recv(4096).decode(errors="ignore").strip().split(",")

    matches = list(set(ids) & set(certs))
    if not matches:
        conn.sendall(b"HTTPC-FALLBACK\n")
        conn.close()
        return

    cid = random.choice(matches)
    seed = certs[cid]
    conn.sendall(f"HTTPC-USE:{cid}\n".encode())

    state = clients.get(ip)
    if not state or state["uses"] >= TEMP_KEY_USES:
        temp = hashlib.sha256(
            f"{ip}{time.time()}{random.random()}".encode()
        ).hexdigest()

        clients[ip] = {"temp": temp, "uses": 1, "seed": seed}
        payload = json.dumps({"temp_key": temp}).encode()
        conn.sendall(crypt(payload, seed))
        conn.close()
        return

    clients[ip]["uses"] += 1

    enc = conn.recv(65535)
    data = crypt(crypt(enc, seed), clients[ip]["temp"])

    resp = http_response(b"Hello (HTTPC secure)")
    out = crypt(crypt(resp, clients[ip]["temp"]), seed)
    conn.sendall(out)
    conn.close()

# ---------------- SERVERS ----------------
def httpc_server():
    s = socket.socket()
    s.bind(("0.0.0.0", HTTPC_PORT))
    s.listen(50)
    print("[HTTPC] Listening on 228")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_httpc, args=(c, a), daemon=True).start()

def http_server():
    s = socket.socket()
    s.bind(("0.0.0.0", HTTP_PORT))
    s.listen(50)
    print("[HTTP] Listening on 80 (fallback)")
    while True:
        c, _ = s.accept()
        c.recv(4096)
        c.sendall(http_response())
        c.close()

# ---------------- START ----------------
sync_keys()
threading.Thread(target=http_server, daemon=True).start()
httpc_server()
