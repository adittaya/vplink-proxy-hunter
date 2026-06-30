import json
import os
import sys

CONFIG_DIR = os.path.expanduser("~/.config/vplink-hunter")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


def _load_dotenv(path=".env"):
    if not os.path.exists(path):
        return {}
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip().strip("\"'")
    return env


def load():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            pass

    dotenv = _load_dotenv()
    if dotenv:
        return {
            "supabase_url": dotenv.get("SUPABASE_URL", ""),
            "anon_key": dotenv.get("SUPABASE_ANON_KEY", ""),
            "service_key": dotenv.get("SUPABASE_SERVICE_KEY", ""),
        }

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


def get_api_key():
    cfg = get()
    key = cfg.get("api_key", "")
    if not key:
        import secrets
        key = secrets.token_urlsafe(24)
        cfg["api_key"] = key
        save(cfg)
    return key
