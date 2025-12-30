import os, json, hashlib, random, shutil, subprocess, threading, time, socket

# ---------------- CONFIG ----------------
CERT_DIR = "./cert"
KEY_REPO = "https://github.com/Idonot-Grief/httpc-keys.git"
SYNC_INTERVAL = 3 * 3600
TEMP_KEY_LIFETIME = 5  # requests

HOST = "0.0.0.0"
PORT = 228

os.makedirs(CERT_DIR, exist_ok=True)

# ---------------- STATE ----------------
client_state = {}  
# ip -> { "temp_key": str, "uses": int, "pub_seed": str }

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

    for f in local - remote:
        try:
            os.remove(os.path.join(CERT_DIR, f))
        except:
            pass

    for f in remote:
        shutil.copyfile(os.path.join(tmp, f), os.path.join(CERT_DIR, f))

    shutil.rmtree(tmp, ignore_errors=True)

def periodic_sync():
    while True:
        try:
            sync_keys_server()
        except Exception as e:
            print("Key sync error:", e)
        time.sleep(SYNC_INTERVAL)

threading.Thread(target=periodic_sync, daemon=True).start()

# ---------------- CRYPTO ----------------
def stream(seed):
    h = hashlib.sha256(seed.encode()).digest()
    while True:
        for b in h:
            yield b
        h = hashlib.sha256(h).digest()

def crypt(data: bytes, seed: str) -> bytes:
    g = stream(seed)
    return bytes(b ^ next(g) for b in data)

# ---------------- CERTS ----------------
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
        return None, None

    cid = random.choice(matches)
    conn.sendall(f"HTTPC-USE:{cid}\n".encode())

    return cid, certs[cid]

# ---------------- TEMP KEY MGMT ----------------
def get_temp_key(ip, pub_seed):
    st = client_state.get(ip)

    if st and st["uses"] < TEMP_KEY_LIFETIME:
        st["uses"] += 1
        return st["temp_key"], False

    temp_key = hashlib.sha256(
        f"{ip}:{time.time()}:{random.random()}".encode()
    ).hexdigest()

    client_state[ip] = {
        "temp_key": temp_key,
        "uses": 1,
        "pub_seed": pub_seed
    }

    return temp_key, True

# ---------------- HTTP ----------------
def http_response(code, body=b"", mime="text/plain"):
    return (
        f"HTTP/1.1 {code} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {mime}\r\n\r\n"
    ).encode() + body

# ---------------- CLIENT HANDLER ----------------
def handle_client(conn, addr):
    ip = addr[0]

    try:
        cid, pub_seed = handshake(conn)
        if not pub_seed:
            conn.close()
            return

        raw = conn.recv(65535)
        if not raw:
            conn.close()
            return

        temp_key, rotated = get_temp_key(ip, pub_seed)

        if rotated:
            payload = json.dumps({
                "temp_key": temp_key,
                "valid_for": TEMP_KEY_LIFETIME
            }).encode()

            enc = crypt(payload, pub_seed)
            conn.sendall(enc)
            return

        # DOUBLE DECRYPT
        inner = crypt(raw, pub_seed)
        plaintext = crypt(inner, temp_key)

        # ---- PROCESS REQUEST HERE ----
        body = b"Hello from HTTPC secure server"

        # DOUBLE ENCRYPT RESPONSE
        resp = http_response(200, body)
        enc1 = crypt(resp, temp_key)
        enc2 = crypt(enc1, pub_seed)

        conn.sendall(enc2)

    except Exception as e:
        print("Client error:", e)
    finally:
        conn.close()

# ---------------- SERVER ----------------
def serve():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(50)
    print(f"[HTTPC] Listening on {PORT}")

    while True:
        conn, addr = s.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        ).start()

# ---------------- STARTUP ----------------
sync_keys_server()
serve()
