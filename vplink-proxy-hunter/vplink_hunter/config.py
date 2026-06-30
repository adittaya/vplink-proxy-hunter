import json
import os
import sys

CONFIG_DIR = os.path.expanduser("~/.config/vplink-hunter")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


def load():
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return None


def save(data: dict):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def prompt_and_save():
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║     FIRST-TIME SUPABASE SETUP            ║")
    print("  ╚══════════════════════════════════════════╝")
    print()
    url = input("  Supabase URL: ").strip()
    anon = input("  Supabase Anon Key: ").strip()
    svc = input("  Supabase Service Key: ").strip()
    if not url or not anon or not svc:
        print("  [!] All fields required.")
        sys.exit(1)
    cfg = {"supabase_url": url, "anon_key": anon, "service_key": svc}
    save(cfg)
    print(f"  [✓] Saved to {CONFIG_PATH}")
    return cfg


def get():
    cfg = load()
    if not cfg:
        cfg = prompt_and_save()
    return cfg
