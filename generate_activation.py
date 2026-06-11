#!/usr/bin/env python3
"""
=============================================================================
  Identity Manager — Activation Code Generator
  ITProAcademy.co.in
  
  Run this script to generate activation codes for customers.
  Usage:
      python3 generate_activation.py
      python3 generate_activation.py --days 365
      python3 generate_activation.py --months 6
=============================================================================
"""

import hashlib
import datetime
import argparse
import sys
import secrets
import string

# ── Must match the key in identity_manager.py ────────────────────────────────
_ACT_KEY     = "ITProAcademy2024SecretKey"
_APP_NAME    = "Identity Manager"
_VENDOR      = "ITProAcademy.co.in"

# ── Preset durations ──────────────────────────────────────────────────────────
PRESETS = {
    "trial"    : (30,   "30-day Trial"),
    "1month"   : (30,   "1 Month"),
    "3months"  : (90,   "3 Months"),
    "6months"  : (180,  "6 Months"),
    "1year"    : (365,  "1 Year"),
    "2years"   : (730,  "2 Years"),
    "lifetime" : (3650, "10 Years / Lifetime"),
}

def _random_salt(length: int = 8) -> str:
    """Generate a cryptographically random uppercase alphanumeric salt."""
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def generate_code(days: int, salt: str = None) -> str:
    """
    Generate a unique activation code for N days.
    Format: IDP-{DAYS:04d}-{HASH16}-{SALT8}
    A fresh random salt is used each time, so every call produces
    a different code — no two customers get the same key.
    """
    if salt is None:
        salt = _random_salt(8)
    msg = f"IDManager|{days}|{_ACT_KEY}|{salt}"
    h   = hashlib.sha256(msg.encode()).hexdigest()[:16].upper()
    return f"IDP-{days:04d}-{h}-{salt}"

def verify_code(code: str) -> int:
    """
    Returns days if valid, else 0.
    Supports both new 4-part format (IDP-DAYS-HASH-SALT)
    and legacy 3-part format (IDP-DAYS-HASH) for backward compatibility.
    """
    try:
        parts = code.strip().upper().split("-")
        if len(parts) < 3 or parts[0] != "IDP":
            return 0
        days = int(parts[1])
        if days < 1:
            return 0

        if len(parts) == 4:
            # New format: IDP-DAYS-HASH16-SALT8
            h_part = parts[2]
            salt   = parts[3]
            msg    = f"IDManager|{days}|{_ACT_KEY}|{salt}"
            expected = hashlib.sha256(msg.encode()).hexdigest()[:16].upper()
            return days if h_part == expected else 0

        elif len(parts) == 3:
            # Legacy format: IDP-DAYS-HASH12 (fixed, no salt)
            h_part   = parts[2]
            msg      = f"IDManager|{days}|{_ACT_KEY}"
            expected = hashlib.sha256(msg.encode()).hexdigest()[:12].upper()
            return days if h_part == expected else 0

    except Exception:
        pass
    return 0

def print_code(days: int, label: str = ""):
    code    = generate_code(days)
    today   = datetime.date.today()
    expiry  = today + datetime.timedelta(days=days)
    label   = label or f"{days} days"
    print(f"\n{'─'*60}")
    print(f"  Product  : {_APP_NAME}")
    print(f"  Vendor   : {_VENDOR}")
    print(f"  Duration : {label} ({days} days)")
    print(f"  Issued   : {today}")
    print(f"  Expires  : {expiry}")
    print(f"{'─'*60}")
    print(f"  ACTIVATION CODE:")
    print(f"  {code}")
    print(f"{'─'*60}")
    print(f"  NOTE: Each generated code is unique (random salt).")
    print(f"        The same duration generates a different code every time.\n")

def interactive_menu():
    print(f"\n{'═'*60}")
    print(f"  {_APP_NAME} — Activation Code Generator")
    print(f"  {_VENDOR}")
    print(f"  Each code is unique — same duration, different code every time.")
    print(f"{'═'*60}\n")

    print("  Select duration:\n")
    options = list(PRESETS.items())
    for i, (key, (days, label)) in enumerate(options, 1):
        print(f"    {i}. {label} ({days} days)")
    print(f"    {len(options)+1}. Custom number of days")
    print(f"    {len(options)+2}. Verify an existing code")
    print(f"    0. Exit\n")

    while True:
        try:
            choice = input("  Enter choice: ").strip()
            if choice == "0":
                print("  Exiting.")
                sys.exit(0)
            choice = int(choice)
        except (ValueError, KeyboardInterrupt):
            print("  Invalid input.")
            continue

        if 1 <= choice <= len(options):
            key, (days, label) = options[choice - 1]
            print_code(days, label)
            another = input("  Generate another? (y/n): ").strip().lower()
            if another != "y":
                break

        elif choice == len(options) + 1:
            try:
                days = int(input("  Enter number of days: ").strip())
                if days < 1:
                    print("  Days must be positive.")
                    continue
                print_code(days, f"Custom — {days} days")
                another = input("  Generate another? (y/n): ").strip().lower()
                if another != "y":
                    break
            except ValueError:
                print("  Invalid number.")

        elif choice == len(options) + 2:
            code = input("  Enter code to verify (e.g. IDP-0365-XXXXXXXXXXXXXXXXXXXX-YYYYYYYY): ").strip()
            days = verify_code(code)
            if days:
                expiry = datetime.date.today() + datetime.timedelta(days=days)
                print(f"\n  ✓ VALID CODE — {days} days")
                print(f"    If activated today, expires: {expiry}\n")
            else:
                print(f"\n  ✗ INVALID CODE — this code is not recognised.\n")
        else:
            print("  Invalid option.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{_APP_NAME} Activation Code Generator — {_VENDOR}"
    )
    parser.add_argument("--days",   type=int, help="Generate code for N days")
    parser.add_argument("--months", type=int, help="Generate code for N months (×30 days)")
    parser.add_argument("--verify", type=str, help="Verify an existing activation code")
    args = parser.parse_args()

    if args.verify:
        days = verify_code(args.verify)
        if days:
            print(f"✓ VALID — {days} days. If activated today, expires: {datetime.date.today() + datetime.timedelta(days=days)}")
        else:
            print("✗ INVALID CODE")
        sys.exit(0 if days else 1)

    if args.days:
        print_code(args.days)
        sys.exit(0)

    if args.months:
        days = args.months * 30
        print_code(days, f"{args.months} months")
        sys.exit(0)

    # No args — launch interactive menu
    interactive_menu()
