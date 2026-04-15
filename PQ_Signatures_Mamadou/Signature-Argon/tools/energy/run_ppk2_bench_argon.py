import argparse
import json
import os
import time
from statistics import mean
import subprocess
import serial

from ppk2_api.ppk2_api import PPK2_API

MEAS_START = "###MEAS_START###"
MEAS_STOP = "###MEAS_STOP###"


def safe_mean(values):
    return mean(values) if values else 0.0


def extract_json_lines(lines):
    out = []
    for line in lines:
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            out.append(s)
    return out


def extract_firmware_identity(json_lines, fallback_alg, fallback_op):
    for line in json_lines:
        try:
            obj = json.loads(line)
            alg = obj.get("alg", fallback_alg)
            op = obj.get("op", fallback_op)
            return alg, op
        except Exception:
            pass
    return fallback_alg, fallback_op


def read_ppk_samples(ppk):
    data = ppk.get_data()
    if data != b"":
        samples, _ = ppk.get_samples(data)
        return samples if samples else []
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ppk-port", required=True)
    parser.add_argument("--serial-port", default="/dev/ttyACM0")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--voltage-mv", type=int, default=3300)
    parser.add_argument("--baseline-s", type=float, default=1.0)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--alg", required=True)
    parser.add_argument("--op", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--flash-cmd", default="")
    args = parser.parse_args()

    ppk = None
    ser = None

    try:
        if args.flash_cmd.strip():
            print("[INFO] Flashing Argon...")
            print(f"[INFO] CMD: {args.flash_cmd}")
            flash = subprocess.run(args.flash_cmd, shell=True, text=True)
            if flash.returncode != 0:
                raise RuntimeError("Flash command failed")
            time.sleep(2)
        else:
            print("[INFO] Flash skipped (firmware already loaded).")

        print("[INFO] Opening serial...")
        ser = serial.Serial(args.serial_port, args.baud, timeout=0.1)
        time.sleep(2)

        print("[INFO] Initializing PPK2...")
        ppk = PPK2_API(args.ppk_port, timeout=1, write_timeout=1, exclusive=True)
        ppk.get_modifiers()
        ppk.set_source_voltage(args.voltage_mv)
        ppk.use_ampere_meter()
        ppk.start_measuring()

        time.sleep(0.5)
        print(f"[INFO] PPK2 ready on {args.ppk_port}")

        serial_lines = []
        baseline_samples = []
        run_samples = []

        measure_active = False
        t_start = None
        t_stop = None

        print("[INFO] Collecting baseline...")
        baseline_t0 = time.time()
        while (time.time() - baseline_t0) <= args.baseline_s:
            baseline_samples.extend(read_ppk_samples(ppk))
            time.sleep(0.002)

        print("[INFO] Scanning serial for markers...")

        deadline = time.time() + 4000

        while True:
            line = ser.readline().decode(errors="ignore")
            if line:
                print(line, end="")
                serial_lines.append(line)

                if MEAS_START in line and not measure_active:
                    measure_active = True
                    t_start = time.time()
                    run_samples = []
                    print("[INFO] Measurement window started.")

                if MEAS_STOP in line:
                    t_stop = time.time()
                    if measure_active:
                        measure_active = False
                        print("[INFO] Measurement window stopped.")
                    break

            if measure_active:
                run_samples.extend(read_ppk_samples(ppk))

            if time.time() > deadline:
                raise RuntimeError("Timeout waiting for Argon markers")

            time.sleep(0.002)

        duration_s = (t_stop - t_start) if (t_start is not None and t_stop is not None) else 0.0

        baseline_mean_ua = safe_mean(baseline_samples)
        run_mean_ua_raw = safe_mean(run_samples)
        run_mean_ua_corrected = run_mean_ua_raw - baseline_mean_ua
        run_mean_ua_corrected_clamped = max(0.0, run_mean_ua_corrected)

        energy_j = (
            (args.voltage_mv / 1000.0)
            * (run_mean_ua_corrected_clamped / 1_000_000.0)
            * duration_s
        )

        json_lines = extract_json_lines(serial_lines)
        real_alg, real_op = extract_firmware_identity(json_lines, args.alg, args.op)

        iters = len(json_lines) if len(json_lines) > 0 else 1
        time_per_op_s = duration_s / iters
        energy_per_op_j = energy_j / iters

        result = {
            "platform": args.platform,
            "alg": real_alg,
            "op": real_op,
            "iters": iters,
            "duration_s": duration_s,
            "time_per_op_s": time_per_op_s,
            "baseline_mean_ua": baseline_mean_ua,
            "run_mean_ua_raw": run_mean_ua_raw,
            "run_mean_ua_corrected": run_mean_ua_corrected_clamped,
            "energy_j": energy_j,
            "energy_per_op_j": energy_per_op_j,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "energy_status": "usable" if run_mean_ua_corrected_clamped > 100.0 else "preliminary",
        }

        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(args.output, "a", encoding="utf-8") as f:
            f.write(json.dumps(result) + "\n")

        raw_jsonl_path = args.output.replace(".jsonl", "_argon_raw.jsonl")
        with open(raw_jsonl_path, "a", encoding="utf-8") as f:
            for line in json_lines:
                f.write(line + "\n")

        print("\n[INFO] Energy result:")
        print(json.dumps(result, indent=2))

    finally:
        if ser is not None:
            try:
                ser.close()
            except Exception:
                pass

        if ppk is not None:
            try:
                ppk.stop_measuring()
            except Exception:
                pass


if __name__ == "__main__":
    main()