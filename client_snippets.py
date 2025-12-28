import os, json, hashlib, shutil, subprocess, socket

# ---------------- CONFIG ----------------
KEY_DIR = "./keys"
KEY_REPO = "https://github.com/Idonot-Grief/httpc-keys.git"

os.makedirs(KEY_DIR, exist_ok=True)

# ---------------- KEY SYNC ----------------
def sync_keys_client():
    tmp = KEY_DIR + "_tmp"
    shutil.rmtree(tmp, ignore_errors=True)

    subprocess.run(
        ["git", "clone", "--depth", "1", KEY_REPO, tmp],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if not os.path.exists(tmp):
        return

    remote = {f for f in os.listdir(tmp) if f.endswith(".cat")}
    local = {f for f in os.listdir(KEY_DIR) if f.endswith(".cat")}

    for f in local - remote:
        try: os.remove(os.path.join(KEY_DIR, f))
        except: pass

    for f in remote:
        shutil.copyfile(os.path.join(tmp, f), os.path.join(KEY_DIR, f))

    shutil.rmtree(tmp, ignore_errors=True)

# ---------------- CRYPTO ----------------
def crypt(data, seed):
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return bytes(b ^ h[i % len(h)] for i, b in enumerate(data))

# ---------------- CERT HELPERS ----------------
def load_ids():
    ids = []
    for f in os.listdir(KEY_DIR):
        if f.endswith(".cat"):
            with open(os.path.join(KEY_DIR, f), encoding="utf-8") as fh:
                ids.append(json.load(fh)["id"])
    return ids

def load_seed(cid):
    with open(os.path.join(KEY_DIR, cid + ".cat"), encoding="utf-8") as fh:
        return json.load(fh)["seed"]

# ---------------- HTTPC REQUEST ----------------
def httpc_handshake(conn):
    """Perform HTTPC handshake. Returns seed if server selects a key, else None."""
    conn.sendall(b"HTTPC-HELLO\n")
    conn.sendall(",".join(load_ids()).encode() + b"\n")
    reply = conn.recv(1024).decode(errors="ignore")
    if "HTTPC-USE:" in reply:
        cid = reply.split(":", 1)[1].strip()
        return load_seed(cid)
    return None
