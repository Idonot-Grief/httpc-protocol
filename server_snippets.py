import os, json, hashlib, random, shutil, subprocess, threading, time

# ---------------- CONFIG ----------------
CERT_DIR = "./cert"
KEY_REPO = "https://github.com/Idonot-Grief/httpc-keys.git"
SYNC_INTERVAL = 3 * 3600  # 3 hours in seconds

os.makedirs(CERT_DIR, exist_ok=True)

# ---------------- KEY SYNC ----------------
def sync_keys_server():
    tmp = CERT_DIR + "_tmp"
    shutil.rmtree(tmp, ignore_errors=True)

    subprocess.run(
        ["git", "clone", "--depth", "1", KEY_REPO, tmp],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if not os.path.exists(tmp):
        return

    remote = {f for f in os.listdir(tmp) if f.endswith(".cat")}
    local = {f for f in os.listdir(CERT_DIR) if f.endswith(".cat")}

    # Remove deleted keys
    for f in local - remote:
        try:
            os.remove(os.path.join(CERT_DIR, f))
        except:
            pass

    # Copy new/updated keys
    for f in remote:
        shutil.copyfile(os.path.join(tmp, f), os.path.join(CERT_DIR, f))

    shutil.rmtree(tmp, ignore_errors=True)

def periodic_sync():
    while True:
        try:
            sync_keys_server()
        except Exception as e:
            print("Error syncing keys:", e)
        time.sleep(SYNC_INTERVAL)

# Start the periodic sync in a background thread
threading.Thread(target=periodic_sync, daemon=True).start()

# ---------------- CRYPTO ----------------
def stream(seed):
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    while True:
        for b in h:
            yield b
        h = hashlib.sha256(h).digest()

def crypt(data, seed):
    g = stream(seed)
    return bytes(b ^ next(g) for b in data)

# ---------------- CERT ----------------
def load_certs():
    out = {}
    for f in os.listdir(CERT_DIR):
        if f.endswith(".cat"):
            with open(os.path.join(CERT_DIR, f), encoding="utf-8") as fh:
                j = json.load(fh)
                out[j["id"]] = j["seed"]
    return out

# ---------------- HANDSHAKE ----------------
def handshake(conn):
    certs = load_certs()
    conn.sendall(b"HTTPC-HELLO\n")
    ids = conn.recv(4096).decode(errors="ignore").strip().split(",")
    matches = list(set(ids) & set(certs))
    if not matches:
        conn.sendall(b"HTTPC-FALLBACK\n")
        return None
    cid = random.choice(matches)
    conn.sendall(f"HTTPC-USE:{cid}\n".encode())
    return certs[cid]

# ---------------- RESPONSE ----------------
def http_response(code, body=b"", mime="text/plain"):
    return (
        f"HTTP/1.1 {code} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {mime}\r\n\r\n"
    ).encode() + body

# ---------------- INITIAL SYNC ----------------
# Run once at startup
sync_keys_server()
