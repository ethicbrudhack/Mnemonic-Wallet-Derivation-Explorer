#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib, base58, os, time, sqlite3, multiprocessing, threading, itertools
from typing import List, Dict
from mnemonic import Mnemonic
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip49, Bip84, Bip86,
    Bip44Coins, Bip49Coins, Bip84Coins, Bip86Coins, Bip44Changes
)
import nacl.signing  # Solana
import json



# ─── USTAWIENIA ────────────────────────────────────────────
CHECKPOINT_FILE = "checkpoint.json"
OUTPUT_FILE      = "znalezione_POPULAR.txt"
POPULAR_WORDS_FN = "popular_words12.txt"
PROCESSES        = 3
MAX_INDEX        = 5
DB_FILE          = "alladdresses.db"
WORD_LENGTHS     = (12, 15, 18, 24)
STRENGTH_MAP     = {12: 128, 15: 160, 18: 192, 24: 256}
DB_RETRIES       = 5
DB_BACKOFF_BASE  = 0.2

# ─── POMOCNICZE ───────────────────────────────────────────

def privkey_to_wif(priv_hex: str, compressed: bool = True) -> str:
    payload = b"\x80" + bytes.fromhex(priv_hex) + (b"\x01" if compressed else b"")
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()


def address_exists_in_db(conn: sqlite3.Connection, address: str, pid: int = None) -> bool:
    attempt = 0
    while True:
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM addresses WHERE address = ?", (address,))
            return cur.fetchone() is not None

        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            who = f"Worker {pid} - " if pid is not None else ""

            if "locked" in msg:
                if attempt < DB_RETRIES:
                    backoff = DB_BACKOFF_BASE * (2 ** attempt)
                    print(f"[⚠️] {stamp} {who}Baza zablokowana (próba {attempt+1}/{DB_RETRIES+1}) – czekam {backoff:.2f}s", flush=True)
                    time.sleep(backoff)
                    attempt += 1
                    continue
                else:
                    print(f"[❌] {stamp} {who}Baza nadal zablokowana – pomijam zapytanie.", flush=True)
                    return False
            else:
                print(f"[❌] {stamp} {who}Błąd SQLite: {exc}", flush=True)
                return False

        except Exception as exc:
            print(f"[❌] Inny błąd przy zapytaniu do DB: {exc}", flush=True)
            return False


# ─── MAPA DERYWACJI ──────────────────────────────────────
COIN_MAP = {
    "BTC": [("BIP44", Bip44, Bip44Coins.BITCOIN),
            ("BIP49", Bip49, Bip49Coins.BITCOIN),
            ("BIP84", Bip84, Bip84Coins.BITCOIN),
            ("BIP86", Bip86, Bip86Coins.BITCOIN)],
    "LTC": [("BIP44", Bip44, Bip44Coins.LITECOIN),
            ("BIP49", Bip49, Bip49Coins.LITECOIN),
            ("BIP84", Bip84, Bip84Coins.LITECOIN)],
    "ETH": [("BIP44", Bip44, Bip44Coins.ETHEREUM)],
    "DOGE":[("BIP44", Bip44, Bip44Coins.DOGECOIN)],
    "XRP": [("BIP44", Bip44, Bip44Coins.RIPPLE)],
    "DASH":[("BIP44", Bip44, Bip44Coins.DASH)],
    "BCH": [("BIP44", Bip44, Bip44Coins.BITCOIN_CASH)],
}

# ─── SOLANA ──────────────────────────────────────

def solana_addresses(seed_phrase: str) -> List[Dict]:
    out: List[Dict] = []
    seed = Bip39SeedGenerator(seed_phrase).Generate()
    base = Bip44.FromSeed(seed, Bip44Coins.SOLANA).Purpose().Coin()
    for i in range(MAX_INDEX):
        node = base.Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
        priv_raw = node.PrivateKey().Raw().ToBytes()
        pub_raw  = nacl.signing.SigningKey(priv_raw).verify_key.encode()
        out.append({
            "coin": "SOL",
            "type": "SOLANA-BIP44",
            "index": i,
            "address": base58.b58encode(pub_raw).decode(),
            "hex": priv_raw.hex(),
        })
    return out

# ─── HD-ADRESY ──────────────────────────────────

def hd_addresses(seed_phrase: str) -> List[Dict]:
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    lst: List[Dict] = []
    for coin, derivs in COIN_MAP.items():
        for name, cls, enum in derivs:
            base = cls.FromSeed(seed_bytes, enum).Purpose().Coin()
            for i in range(MAX_INDEX):
                node = base.Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
                addr = node.PublicKey().ToAddress()
                if coin == "BCH" and addr.startswith("bitcoincash:"):
                    addr = addr.split(":", 1)[1]
                priv_hex = node.PrivateKey().Raw().ToHex()
                lst.append({
                    "coin": coin,
                    "type": f"{coin}-{name}",
                    "index": i,
                    "address": addr,
                    "wif": privkey_to_wif(priv_hex) if coin in {"BTC","LTC","DOGE","BCH","DASH"} else priv_hex,
                })
    lst.extend(solana_addresses(seed_phrase))
    return lst

# ─── PRODUCER ───────────────────────────────────

def load_popular_words() -> List[str]:
    """Wczytuje popularne słowa z pliku i filtruje tylko te z listy BIP39."""
    mnemo = Mnemonic("english")
    with open(POPULAR_WORDS_FN, encoding="utf-8") as f:
        return [w.strip() for w in f if w.strip() in mnemo.wordlist]


import json

CHECKPOINT_FILE = "checkpoint.json"


def producer(q, tot_combos, done_combos, seed_ok, lock):
    mnemo  = Mnemonic("english")
    words  = load_popular_words()

    combos = sum(len(words)**l for l in WORD_LENGTHS)
    with lock:
        tot_combos.value = combos

    # próba wczytania checkpointa
    start_index = 0
    start_length = WORD_LENGTHS[0]
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                start_index = data.get("index", 0)
                start_length = data.get("length", WORD_LENGTHS[0])
                print(f"[↩️] Wznawiam od kombinacji {start_index:,} (dla długości {start_length})", flush=True)
        except Exception:
            pass

    last_pct = -1
    global_index = 0

    for length in WORD_LENGTHS:
        total_for_length = len(words)**length
        for tup in itertools.product(words, repeat=length):
            global_index += 1
            if length < start_length or (length == start_length and global_index < start_index):
                continue  # pomiń wcześniejsze kombinacje

            with lock:
                done_combos.value += 1
                pct = done_combos.value / tot_combos.value * 100

            if int(pct * 100) != int(last_pct * 100) or done_combos.value % 1000 == 0:
                print(f"[{pct:6.2f}%]", flush=True)
                last_pct = pct

                # zapis checkpointa co 1000 kroków
                with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                    json.dump({"index": global_index, "length": length}, f)

            phrase = " ".join(tup)
            if mnemo.check(phrase):
                q.put(phrase)
                with lock:
                    seed_ok.value += 1

    for _ in range(PROCESSES):
        q.put(None)

# ─── WORKER ───────────────────────────────────

def worker(q, io_lock, seed_ok, addr_cnt, lock, wid):
    db_uri = f"file:{DB_FILE}?mode=ro"
    conn = sqlite3.connect(db_uri, uri=True, timeout=5, check_same_thread=False)

    while True:
        seed = q.get()
        if seed is None:
            break

        addrs = hd_addresses(seed)
        hit = False
        matched = []  # lista trafionych adresów

        # sprawdzanie bez wypisywania wszystkich adresów
        for d in addrs:
            if address_exists_in_db(conn, d["address"], pid=wid):
                hit = True
                matched.append(d)

        # jeśli HIT — loguj do pliku
        if hit:
            print(f"[💥] Worker {wid}: ZNALEZIONO HIT ({len(matched)} adresów)", flush=True)
            with io_lock, open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write(f"Seed: {seed}\n")
                for d in addrs:
                    f.write(f"{d['type']}[{d['index']}]: {d['address']}\n")
                    f.write(f"{'Priv WIF:' if 'wif' in d else 'Priv HEX:'} {d['wif'] if 'wif' in d else d['hex']}\n")
                f.write("HITS:\n")
                for m in matched:
                    if 'wif' in m:
                        f.write(f"  -> {m['type']}[{m['index']}]: {m['address']}  (Priv WIF: {m['wif']})\n")
                    else:
                        f.write(f"  -> {m['type']}[{m['index']}]: {m['address']}  (Priv HEX: {m['hex']})\n")
                f.write("✅ HIT!\n")
                f.write("------------------------------------------------\n")

        with lock:
            addr_cnt.value += len(addrs)

# ─── MAIN ───────────────────────────────────

def main():
    if not os.path.exists(DB_FILE):
        print("Brak bazy:", DB_FILE)
        return

    mgr   = multiprocessing.Manager()
    seed_ok = mgr.Value('i',0)
    addr_cnt= mgr.Value('i',0)
    tot_c   = mgr.Value('i',0)
    done_c  = mgr.Value('i',0)
    lock    = mgr.Lock()
    io_lock = mgr.Lock()
    q       = multiprocessing.Queue(PROCESSES*2)

    def printer():
        while True:
            with lock:
                print(f"[📊] Seeds: {seed_ok.value}, Addrs: {addr_cnt.value}", flush=True)
            time.sleep(2)
    threading.Thread(target=printer, daemon=True).start()

    prod = multiprocessing.Process(target=producer,
           args=(q, tot_c, done_c, seed_ok, lock))
    prod.start()

    ws = [multiprocessing.Process(target=worker,
          args=(q, io_lock, seed_ok, addr_cnt, lock, i))
          for i in range(PROCESSES)]
    for w in ws:
        w.start()

    prod.join()
    for _ in ws:
        q.put(None)
    for w in ws:
        w.join()

    print(f"FINISHED  seeds:{seed_ok.value}  addrs:{addr_cnt.value}", flush=True)


if __name__ == "__main__":
    main()
