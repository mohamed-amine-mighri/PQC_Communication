#!/usr/bin/env python3
"""
Capture ML-KEM MQTT communication benchmark results from Particle Argon serial port.
Uses the same ===JSON_START=== / ===JSON_END=== delimiters as the standalone benchmark.

This script adds MQTT-specific summary output (crypto vs network time breakdown).

IMPORTANT: Close 'particle serial monitor' before running this script!

Usage:
    python scripts/capture_mqtt_benchmark.py --port COM6
    python scripts/capture_mqtt_benchmark.py --port COM6 --timeout 600

Steps:
    1. Flash MQTT benchmark to Argon (BENCHMARK_MQTT_MODE)
    2. Ensure ESP32 server/client is running (the counterpart)
    3. Close any serial monitors
    4. Run this script
    5. Press RESET on Argon if needed
"""

import serial
import serial.tools.list_ports
import json
import os
import sys
import argparse
import time as _time
from datetime import datetime

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT  = 600  # 10 min — MQTT iterations take longer due to network


def find_serial_port():
    """Auto-detect Particle Argon serial port."""
    ports = serial.tools.list_ports.comports()
    for p in ports:
        desc = (p.description or "").lower()
        if "particle" in desc or "argon" in desc or "usb serial" in desc:
            print(f"[INFO] Auto-detected: {p.device} ({p.description})")
            return p.device
    if ports:
        print(f"[INFO] Using first available port: {ports[0].device} ({ports[0].description})")
        return ports[0].device
    return "COM6" if sys.platform.startswith("win") else "/dev/ttyUSB0"


def open_serial_with_retry(port, baudrate, max_retries=10, retry_delay=3):
    """Try to open the serial port with retries."""
    for attempt in range(1, max_retries + 1):
        try:
            ser = serial.Serial(port, baudrate, timeout=1)
            print(f"[OK] Serial port {port} opened successfully.")
            return ser
        except serial.SerialException as e:
            err_str = str(e).lower()
            if "access" in err_str or "permission" in err_str or "denied" in err_str:
                print(f"\n[ERROR] Port {port} is in use by another program!")
                print("        Close 'particle serial monitor' or any other serial tool first.")
                sys.exit(1)
            else:
                print(f"[RETRY {attempt}/{max_retries}] Cannot open {port}: {e}")
                if attempt < max_retries:
                    _time.sleep(retry_delay)
    print(f"[ERROR] Could not open {port} after {max_retries} attempts.")
    sys.exit(1)


def capture(port, baudrate, timeout):
    """Listen on serial port, return list of parsed JSON objects."""
    ser = open_serial_with_retry(port, baudrate)
    _time.sleep(2)

    results   = []
    json_lines = []
    in_json   = False
    all_lines = []
    t0 = _time.time()

    print("[INFO] Listening for MQTT benchmark output... (press RESET on Argon if needed)\n")

    try:
        while (_time.time() - t0) < timeout:
            try:
                raw = ser.readline()
            except serial.SerialException:
                print("\n[WARN] Serial connection lost. Reconnecting...")
                try:
                    ser.close()
                except Exception:
                    pass
                _time.sleep(3)
                ser = open_serial_with_retry(port, baudrate, max_retries=5)
                _time.sleep(2)
                t0 = _time.time()
                continue

            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            print(line)
            all_lines.append(line)

            if line == "===JSON_START===":
                in_json = True
                json_lines = []
                continue

            if line == "===JSON_END===" and in_json:
                in_json = False
                blob = "\n".join(json_lines)
                try:
                    obj = json.loads(blob)
                    results.append(obj)
                    print(f"\n{'='*60}")
                    print(f"  JSON result #{len(results)} captured successfully!")
                    print(f"{'='*60}\n")
                except json.JSONDecodeError as e:
                    print(f"\n[ERROR] JSON parse error: {e}")
                    os.makedirs(RESULTS_DIR, exist_ok=True)
                    err_path = os.path.join(RESULTS_DIR,
                        f"mqtt_parse_error_{datetime.now():%Y%m%d_%H%M%S}.txt")
                    with open(err_path, "w") as f:
                        f.write(blob)
                    print(f"[SAVED] Raw text: {err_path}\n")
                continue

            if in_json:
                json_lines.append(line)

            if "MQTT Benchmark mode complete" in line or "MQTT BENCHMARK] Complete" in line:
                print("\n[INFO] MQTT Benchmark complete signal received.")
                _time.sleep(2)
                break

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user (Ctrl+C).")
    finally:
        ser.close()
        print("[INFO] Serial port closed.")

    # Save raw serial log
    if all_lines:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        log_path = os.path.join(RESULTS_DIR,
            f"mqtt_serial_log_{datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(log_path, "w") as f:
            f.write("\n".join(all_lines))
        print(f"[SAVED] Full serial log: {log_path}")

    return results


def save_results(results):
    """Save each result as a JSON file with MQTT-specific summary."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if not results:
        print("\n[WARN] No JSON results captured.")
        print("       Possible causes:")
        print("       - Counterpart device (ESP32) not running")
        print("       - WiFi/MQTT connection failed")
        print("       - BENCHMARK_MQTT_MODE not enabled in main.cpp")
        print("       - Serial monitor was open (close it first)")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for i, r in enumerate(results):
        variant = r.get("variant", "unknown").replace("-", "_")
        role    = r.get("role", "unknown")
        iters   = r.get("num_iterations", 1)
        fname   = f"mqtt_benchmark_{variant}_{role}_{iters}iter_{ts}.json"
        fpath   = os.path.join(RESULTS_DIR, fname)

        with open(fpath, "w") as f:
            json.dump(r, f, indent=2)

        print(f"\n[SAVED] {fpath}")

        # Print MQTT-specific summary
        summary = r.get("summary", {})
        if summary:
            print(f"\n  MQTT Benchmark Summary ({r.get('variant')}, role={role}, {iters} iterations):")
            print(f"  {'─'*55}")
            print(f"    Transport setup     : {r.get('transport_setup_ms', 0):10.3f} ms")
            print(f"    Avg handshake init  : {summary.get('avg_handshake_init_ms', 0):10.3f} ms")
            print(f"    Avg keygen          : {summary.get('avg_keygen_ms', 0):10.3f} ms")
            print(f"    Avg PK transfer     : {summary.get('avg_pk_transfer_ms', 0):10.3f} ms")
            print(f"    Avg encapsulation   : {summary.get('avg_encaps_ms', 0):10.3f} ms")
            print(f"    Avg CT transfer     : {summary.get('avg_ct_transfer_ms', 0):10.3f} ms")
            print(f"    Avg decapsulation   : {summary.get('avg_decaps_ms', 0):10.3f} ms")
            print(f"    Avg SS transfer     : {summary.get('avg_ss_transfer_ms', 0):10.3f} ms")
            print(f"  {'─'*55}")
            print(f"    Avg total handshake : {summary.get('avg_total_handshake_ms', 0):10.3f} ms")
            print(f"    Min total           : {summary.get('min_total_handshake_ms', 0):10.3f} ms")
            print(f"    Max total           : {summary.get('max_total_handshake_ms', 0):10.3f} ms")
            print(f"    Stddev              : {summary.get('stddev_total_handshake_ms', 0):10.3f} ms")
            print(f"  {'─'*55}")
            print(f"    Avg crypto time     : {summary.get('avg_crypto_ms', 0):10.3f} ms ({summary.get('crypto_percent', 0):.1f}%)")
            print(f"    Avg network time    : {summary.get('avg_network_ms', 0):10.3f} ms ({summary.get('network_percent', 0):.1f}%)")
            print(f"  {'─'*55}")
            print(f"    Successful verifs   : {r.get('successful_verifications', 0)}/{iters}")

    print(f"\n{'='*60}")
    print(f"  {len(results)} result file(s) saved to {RESULTS_DIR}/")
    print(f"{'='*60}")


def main():
    ap = argparse.ArgumentParser(
        description="Capture ML-KEM MQTT benchmark results from Particle Argon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Steps:
  1. Flash Argon with BENCHMARK_MQTT_MODE enabled
  2. Ensure counterpart (ESP32) is running as server/client
  3. Close 'particle serial monitor'
  4. Run: python scripts/capture_mqtt_benchmark.py --port COM6
  5. Press RESET on Argon if needed
  6. Results saved to results/ folder as JSON
""")
    ap.add_argument("--port",     default=None, help="Serial port (default: auto-detect)")
    ap.add_argument("--baudrate", default=DEFAULT_BAUDRATE, type=int)
    ap.add_argument("--timeout",  default=DEFAULT_TIMEOUT, type=int,
                    help=f"Max seconds to listen (default: {DEFAULT_TIMEOUT})")
    args = ap.parse_args()

    port = args.port or find_serial_port()

    print("=" * 60)
    print("  ML-KEM MQTT Communication Benchmark Capture Tool")
    print("=" * 60)
    print(f"  Port      : {port}")
    print(f"  Baudrate  : {args.baudrate}")
    print(f"  Timeout   : {args.timeout}s")
    print(f"  Output    : {RESULTS_DIR}")
    print("=" * 60)

    results = capture(port, args.baudrate, args.timeout)
    save_results(results)


if __name__ == "__main__":
    main()
