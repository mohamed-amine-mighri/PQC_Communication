import argparse
import json
import os
import signal
import subprocess
import time
from statistics import mean

from ppk2_api.ppk2_api import PPK2_API

MEAS_START = "###MEAS_START###"
MEAS_STOP = "###MEAS_STOP###"


def safe_mean(values):
    return mean(values) if values else 0.0


def extract_json_lines(text):
    json_lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            json_lines.append(s)
    return json_lines


def read_ppk_samples(ppk):
    data = ppk.get_data()
    if data != b"":
        samples, raw_digital = ppk.get_samples(data)
        return samples if samples else []
    return []


def terminate_process_group(proc):
    if proc is None:
        return

    try:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            time.sleep(1.0)
    except Exception:
        pass

    try:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            time.sleep(0.5)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ppk-port", default="/dev/ttyACM0")
    parser.add_argument("--voltage-mv", type=int, default=3300)
    parser.add_argument("--baseline-s", type=float, default=1.0)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--alg", required=True)
    parser.add_argument("--op", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cmd", required=True)
    args = parser.parse_args()

    ppk = None
    proc = None

    try:
        print("[INFO] Initializing PPK2...")
        ppk = PPK2_API(args.ppk_port, timeout=1, write_timeout=1, exclusive=True)
        ppk.get_modifiers()
        ppk.set_source_voltage(args.voltage_mv)
        ppk.use_source_meter()
        ppk.toggle_DUT_power("ON")
        ppk.start_measuring()

        time.sleep(0.5)

        print(f"[INFO] PPK2 ready on {args.ppk_port}")
        print("[INFO] Launching benchmark command...")
        print(f"[INFO] CMD: {args.cmd}")

        proc = subprocess.Popen(
            args.cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            start_new_session=True,   # important
        )

        stdout_lines = []
        measure_active = False
        baseline_active = False

        baseline_samples = []
        run_samples = []

        t_start = None
        t_stop = None
        baseline_t0 = None
        saw_stop = False

        while True:
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None:
                break

            if line:
                print(line, end="")
                stdout_lines.append(line)

                if MEAS_START in line and not measure_active:
                    measure_active = True
                    baseline_active = False
                    t_start = time.time()
                    run_samples = []
                    print("[INFO] Measurement window started.")

                if MEAS_STOP in line and measure_active:
                    t_stop = time.time()
                    measure_active = False
                    saw_stop = True
                    print("[INFO] Measurement window stopped.")
                    break

            if not measure_active and t_start is None:
                if baseline_t0 is None:
                    baseline_t0 = time.time()
                    baseline_active = True

                if baseline_active and (time.time() - baseline_t0) <= args.baseline_s:
                    baseline_samples.extend(read_ppk_samples(ppk))
                else:
                    baseline_active = False

            if measure_active:
                run_samples.extend(read_ppk_samples(ppk))

            time.sleep(0.002)

        # Après MEAS_STOP, on arrête monitor/idf.py pour libérer le port série
        if saw_stop:
            terminate_process_group(proc)

        try:
            remaining = proc.communicate(timeout=2)[0]
        except Exception:
            remaining = ""

        if remaining:
            print(remaining, end="")
            stdout_lines.append(remaining)

        try:
            proc.wait(timeout=5)
        except Exception:
            pass

        full_stdout = "".join(stdout_lines)
        json_lines = extract_json_lines(full_stdout)

        duration_s = (t_stop - t_start) if (t_start is not None and t_stop is not None) else 0.0

        baseline_mean_ua = safe_mean(baseline_samples)
        run_mean_ua_raw = safe_mean(run_samples)
        run_mean_ua_corrected = run_mean_ua_raw - baseline_mean_ua
        run_mean_ua_corrected_clamped = max(0.0, run_mean_ua_corrected)

        energy_j = (args.voltage_mv / 1000.0) * (run_mean_ua_corrected_clamped / 1_000_000.0) * duration_s

        result = {
            "platform": args.platform,
            "alg": args.alg,
            "op": args.op,
            "ppk_port": args.ppk_port,
            "voltage_mv": args.voltage_mv,
            "baseline_s": args.baseline_s,
            "duration_s": duration_s,
            "baseline_mean_ua": baseline_mean_ua,
            "run_mean_ua_raw": run_mean_ua_raw,
            "run_mean_ua_corrected": run_mean_ua_corrected,
            "run_mean_ua_corrected_clamped": run_mean_ua_corrected_clamped,
            "energy_j": energy_j,
            "baseline_samples": len(baseline_samples),
            "run_samples": len(run_samples),
            "returncode": proc.returncode,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "command": args.cmd,
            "marker_start_seen": t_start is not None,
            "marker_stop_seen": t_stop is not None,
            "esp_jsonl_count": len(json_lines),
            "esp_jsonl_preview": json_lines[:3],
            "stdout_tail": full_stdout[-3000:],
            "energy_valid": run_mean_ua_corrected_clamped > 100.0,
            "energy_status": "usable" if run_mean_ua_corrected_clamped > 100.0 else "preliminary",
        }

        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(args.output, "a", encoding="utf-8") as f:
            f.write(json.dumps(result) + "\n")

        raw_jsonl_path = args.output.replace(".jsonl", "_esp_raw.jsonl")
        with open(raw_jsonl_path, "a", encoding="utf-8") as f:
            for line in json_lines:
                f.write(line + "\n")

        print("\n[INFO] Energy result:")
        print(json.dumps(result, indent=2))

    finally:
        if proc is not None:
            terminate_process_group(proc)
            try:
                proc.wait(timeout=5)
            except Exception:
                pass

        if ppk is not None:
            try:
                ppk.stop_measuring()
            except Exception:
                pass
            try:
                ppk.toggle_DUT_power("OFF")
            except Exception:
                pass


if __name__ == "__main__":
    main()