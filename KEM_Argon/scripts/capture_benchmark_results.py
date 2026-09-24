#!/usr/bin/env python3
"""
Capture ML-KEM benchmark results from Particle Argon serial port.
Looks for JSON blocks delimited by ===JSON_START=== / ===JSON_END===
and saves them to the results/ folder.

IMPORTANT: Close 'particle serial monitor' before running this script!
           Only ONE program can use a serial port at a time on Windows.

Usage:
    python scripts/capture_benchmark_results.py --port COM6
    python scripts/capture_benchmark_results.py --port COM6 --timeout 300

Steps:
    1. Flash device:  particle flash <device-id>
    2. Close any serial monitors
    3. Run this script
    4. Press RESET button on Argon if benchmark already ran
"""

import serial
import serial.tools.list_ports
import json
import os
import sys
import argparse
import time as _time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT  = 300   # seconds (5 min — enough for 10 iterations)


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
    """Try to open the serial port with retries (handles device reboot)."""
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
                print("        Then run this script again.\n")
                sys.exit(1)
            else:
                print(f"[RETRY {attempt}/{max_retries}] Cannot open {port}: {e}")
                if attempt < max_retries:
                    print(f"        Retrying in {retry_delay}s (device may be rebooting)...")
                    _time.sleep(retry_delay)
    print(f"[ERROR] Could not open {port} after {max_retries} attempts.")
    sys.exit(1)


def capture(port, baudrate, timeout):
    """Listen on serial port, return list of parsed JSON objects."""
    ser = open_serial_with_retry(port, baudrate)
    _time.sleep(2)  # Wait for device to settle

    results = []
    json_lines = []
    in_json = False
    all_lines = []  # Keep all output for fallback save
    t0 = _time.time()

    print("[INFO] Listening... (press RESET on Argon if benchmark already ran)\n")

    try:
        while (_time.time() - t0) < timeout:
            try:
                raw = ser.readline()
            except serial.SerialException:
                # Device disconnected/rebooted — try to reconnect
                print("\n[WARN] Serial connection lost. Reconnecting...")
                try:
                    ser.close()
                except Exception:
                    pass
                _time.sleep(3)
                ser = open_serial_with_retry(port, baudrate, max_retries=5)
                _time.sleep(2)
                t0 = _time.time()  # Reset timeout after reconnect
                continue

            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # Echo to console
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
                    print(f"\n{'='*50}")
                    print(f"  JSON result #{len(results)} captured successfully!")
                    print(f"{'='*50}\n")
                except json.JSONDecodeError as e:
                    print(f"\n[ERROR] JSON parse error: {e}")
                    os.makedirs(RESULTS_DIR, exist_ok=True)
                    err_path = os.path.join(RESULTS_DIR,
                        f"parse_error_{datetime.now():%Y%m%d_%H%M%S}.txt")
                    with open(err_path, "w") as f:
                        f.write(blob)
                    print(f"[SAVED] Raw text saved to {err_path} for debugging\n")
                continue

            if in_json:
                json_lines.append(line)

            # Stop when device says it's done
            if "complete. Device idle" in line or "Multi-iteration complete" in line:
                print("\n[INFO] Benchmark complete signal received.")
                _time.sleep(2)
                break

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user (Ctrl+C).")
    finally:
        ser.close()
        print("[INFO] Serial port closed.")

    # Fallback: save raw serial log
    if all_lines:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        log_path = os.path.join(RESULTS_DIR,
            f"serial_log_{datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(log_path, "w") as f:
            f.write("\n".join(all_lines))
        print(f"[SAVED] Full serial log: {log_path}")

    return results


def save_results(results):
    """Save each result as a separate JSON file in the results/ folder."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if not results:
        print("\n[WARN] No JSON results captured.")
        print("       Possible causes:")
        print("       - Device is crash-looping (red blink)")
        print("       - BENCHMARK_MODE not enabled in main.cpp")
        print("       - Serial monitor was open (close it first)")
        print("       - Benchmark didn't finish before timeout")
        print("\n       Check the serial_log_*.txt file in results/ for raw output.")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for i, r in enumerate(results):
        variant = r.get("variant", "unknown").replace("-", "_")
        iters = r.get("num_iterations", 1)
        fname = f"benchmark_{variant}_{iters}iter_{ts}.json"
        fpath = os.path.join(RESULTS_DIR, fname)

        with open(fpath, "w") as f:
            json.dump(r, f, indent=2)

        print(f"[SAVED] {fpath}")
        
        # Print quick summary
        summary = r.get("summary", {})
        if summary:
            print(f"\n  Quick Summary ({r.get('variant', '?')}, {iters} iterations):")
            for op_name in ["key_generation", "encapsulation", "decapsulation", "total"]:
                op = summary.get(op_name, {})
                avg = op.get("avg_time_ms", 0)
                print(f"    {op_name:20s}: {avg:8.3f} ms (avg)")

    print(f"\n{'='*50}")
    print(f"  {len(results)} result file(s) saved to {RESULTS_DIR}/")
    print(f"{'='*50}")


def main():
    ap = argparse.ArgumentParser(
        description="Capture ML-KEM benchmarks from Particle Argon serial port",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Steps:
  1. Close 'particle serial monitor' if it's running
  2. Flash device: particle flash <device-id>
  3. Run: python scripts/capture_benchmark_results.py --port COM6
  4. Press RESET on Argon if benchmark already ran
  5. Results saved to results/ folder as JSON
""")
    ap.add_argument("--port",     default=None, help="Serial port (default: auto-detect)")
    ap.add_argument("--baudrate", default=DEFAULT_BAUDRATE, type=int)
    ap.add_argument("--timeout",  default=DEFAULT_TIMEOUT, type=int,
                    help=f"Max seconds to listen (default: {DEFAULT_TIMEOUT})")
    args = ap.parse_args()

    port = args.port or find_serial_port()

    print("=" * 50)
    print("  ML-KEM Benchmark Capture Tool")
    print("=" * 50)
    print(f"  Port      : {port}")
    print(f"  Baudrate  : {args.baudrate}")
    print(f"  Timeout   : {args.timeout}s")
    print(f"  Output    : {RESULTS_DIR}")
    print("=" * 50)

    results = capture(port, args.baudrate, args.timeout)
    save_results(results)


if __name__ == "__main__":
    main()
