#!/usr/bin/env python3
"""
openppp2 v2.2.0 config migration tool (v2.1.10 -> v2.2.0).

Migrates a v2.1.10 server/client/proxy JSON configuration to the v2.2.0
breaking format:

  - key.protocol / key.protocol-key       removed (record layer owns data path)
  - key.transport                         must be an AEAD name (fail-closed);
                                          CFB names are rewritten to aes-256-gcm
  - key.plaintext                         removed (conflicts with mandatory AEAD)
  - transport-auth.enabled (server/client) removed (mandatory on plain carriers)
  - transport-auth.keys[]                 required: id + secret-file + state;
                                          auto-created from a generated secret
  - secrets/transport.key                 generated (32 bytes hex, mode 0600)

Usage:
  python3 migrate-config.py server.json [-o out.json] [--dry-run] [--gen-secret]
  python3 migrate-config.py client_proxy.json [-o out.json] [--dry-run] [--gen-secret]

Exit code 0: migration produced valid v2.2.0 config (dry-run: would produce).
Exit code 1: input invalid / migration failed.
"""

import argparse
import json
import os
import secrets
import sys

CANONICAL_KEY_ID = "primary"
DEFAULT_TIMEOUT_MS = 5000
AEAD_TRANSPORT = "aes-256-gcm"

WARNINGS = []


def log_warning(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  WARN: {msg}", file=sys.stderr)


def canonical_key_id(key_id: str) -> bool:
    # Mirrors IsCanonicalKeyId: 1..64 chars, [A-Za-z0-9._-]
    return 1 <= len(key_id) <= 64 and all(
        c.isalnum() or c in "._-" for c in key_id)


def migrate(config: dict, path: str) -> dict:
    if not isinstance(config, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")

    # Flat key snippet (e.g. android_default_key.json) vs full config.
    flat_key = "key" not in config and "transport" in config

    # --- key section -----------------------------------------------------
    key = config.get("key")
    if not isinstance(key, dict):
        if flat_key:
            key = config   # operate in place: flat snippets have no wrapper
        else:
            raise ValueError(f"{path}: missing 'key' object")
    if not flat_key:
        key = dict(key)

    if "protocol" in key or "protocol-key" in key:
        removed = [k for k in ("protocol", "protocol-key") if k in key]
        for k in removed:
            del key[k]
        print(f"  - key.{'/'.join(removed)}: removed (record layer owns the data path)")

    transport = str(key.get("transport", "aes-256-cfb"))
    if "gcm" not in transport.lower() and "chacha20" not in transport.lower() and \
            "ccm" not in transport.lower():
        print(f"  - key.transport: {transport} -> {AEAD_TRANSPORT} (mandatory AEAD; CFB fail-closed)")
        key["transport"] = AEAD_TRANSPORT
    elif "simd-" in transport.lower():
        print(f"  - key.transport: {transport} -> {AEAD_TRANSPORT} (unauthenticated SIMD GCM is not allowed)")
        key["transport"] = AEAD_TRANSPORT

    if "plaintext" in key:
        del key["plaintext"]
        print("  - key.plaintext: removed (conflicts with mandatory AEAD record layer)")

    if flat_key:
        config.update(key)
    else:
        config["key"] = key

    # --- transport-auth section -----------------------------------------
    ta = config.get("transport-auth")
    if isinstance(ta, dict):
        ta = dict(ta)
        ta.pop("enabled", None)
        if "handshake-timeout-ms" not in ta:
            ta["handshake-timeout-ms"] = DEFAULT_TIMEOUT_MS
            print(f"  + transport-auth.handshake-timeout-ms: {DEFAULT_TIMEOUT_MS} (default)")
    else:
        ta = {"handshake-timeout-ms": DEFAULT_TIMEOUT_MS}
        print(f"  + transport-auth.handshake-timeout-ms: {DEFAULT_TIMEOUT_MS} (auto-created)")

    keys = ta.get("keys")
    if not isinstance(keys, list) or not keys:
        base = os.path.dirname(os.path.abspath(path))
        secret_file = os.path.join(base, "secrets", "transport.key")
        keys = [{
            "id": CANONICAL_KEY_ID,
            "secret-file": "./secrets/transport.key",
            "state": "active",
        }]
        ta["keys"] = keys
        print(f"  + transport-auth.keys[0]: id={CANONICAL_KEY_ID} secret-file=./secrets/transport.key (auto-created)")
        if not os.path.exists(secret_file):
            log_warning(f"secret file not found: {secret_file}; run with --gen-secret or create a 32-byte hex file")
    else:
        for i, k in enumerate(keys):
            if not isinstance(k, dict):
                raise ValueError(f"{path}: transport-auth.keys[{i}] must be an object")
            kid = str(k.get("id", ""))
            if not canonical_key_id(kid):
                raise ValueError(f"{path}: transport-auth.keys[{i}].id invalid canonical key id: {kid!r}")
            k.pop("enabled", None)

    config["transport-auth"] = ta

    # --- role enable flags (mandatory now) ------------------------------
    for role in ("server", "client"):
        section = config.get(role)
        if isinstance(section, dict):
            role_ta = section.get("transport-auth")
            if isinstance(role_ta, dict) and "enabled" in role_ta:
                del role_ta["enabled"]
                print(f"  - {role}.transport-auth.enabled: removed (mandatory on plain carriers)")

    return config


def gen_secret(path: str) -> None:
    secret = secrets.token_hex(32)  # 64 hex chars = 32 bytes
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret + "\n")
    os.chmod(path, 0o600)
    print(f"  + generated secret file: {path} (32 bytes hex, mode 0600)")


def main() -> int:
    ap = argparse.ArgumentParser(description="openppp2 v2.2.0 config migration")
    ap.add_argument("input", help="v2.1.10 JSON config")
    ap.add_argument("-o", "--output", help="output path (default: stdout)")
    ap.add_argument("--dry-run", action="store_true", help="print planned changes without writing")
    ap.add_argument("--gen-secret", action="store_true",
                    help="generate secrets/transport.key next to the input")
    args = ap.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read {args.input}: {e}", file=sys.stderr)
        return 1

    print(f"migrating {args.input} to v2.2.0 format ({'dry-run' if args.dry_run else 'write'})")

    if args.gen_secret:
        base = os.path.dirname(os.path.abspath(args.input))
        secret_file = os.path.join(base, "secrets", "transport.key")
        gen_secret(secret_file)

    try:
        migrated = migrate(config, args.input)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if WARNINGS:
        print("pending actions:")
        for w in WARNINGS:
            print(f"  - {w}")

    if not args.dry_run:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(migrated, f, indent=2, ensure_ascii=False)
                f.write("\n")
            print(f"wrote {args.output}")
        else:
            print(json.dumps(migrated, indent=2, ensure_ascii=False))
    else:
        print("dry-run: no file written")

    print("migration OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
