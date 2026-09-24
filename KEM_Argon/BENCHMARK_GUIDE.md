# ML-KEM Benchmarking System - Quick Start Guide

## Overview

The ML-KEM benchmarking system measures:
- **Key Generation**: Time and memory for `mlkem_keypair(pk, sk)`
- **Encapsulation**: Time and memory for `mlkem_enc(ct, ss, pk)`
- **Decapsulation**: Time and memory for `mlkem_dec(ss, ct, sk)`
- **Total Process**: Combined time for all three operations
- **Verification**: Confirms that shared secrets match

## Quick Start

### Step 1: Enable Benchmark Mode

Edit [src/main.cpp](../src/main.cpp) and uncomment the benchmark mode:

```cpp
#define BENCHMARK_MODE          // Run performance benchmarks
//#define BENCHMARK_ITERATIONS 5  // Number of iterations (optional)
// #define client                   // Disable regular modes
// #define server
```

### Step 2: Compile and Flash

```bash
# Option A: Build and flash using Particle CLI
particle compile .
particle flash <device-id>

# Option B: Use VS Code Particle Workbench
# Press Ctrl+Shift+P and select "Particle: Flash"
```

### Step 3: Monitor Serial Output

After flashing, open the serial monitor:

```bash
particle serial monitor --follow
# OR
particle serial list  # to find COM port
particle serial monitor <COM_PORT>
```

You should see output like:
```
[BENCHMARK] Starting ML-KEM performance measurement...
[BENCHMARK] Variant: ML-KEM-768
[BENCHMARK] Measuring key generation...
[BENCHMARK] Keygen time: 38 ms
[BENCHMARK] Measuring encapsulation...
[BENCHMARK] Encapsulation time: 32 ms
[BENCHMARK] Measuring decapsulation...
[BENCHMARK] Decapsulation time: 35 ms
...
========== BENCHMARK RESULTS ==========
{
  "variant": "ML-KEM-768",
  "timestamp_ms": 45230,
  ...
}
```

### Step 4: Capture Results to JSON

Use the provided Python script to capture the JSON output:

```bash
# Auto-detect port and save results
python scripts/capture_benchmark_results.py

# Or specify port manually
python scripts/capture_benchmark_results.py --port COM3

# With custom timeout
python scripts/capture_benchmark_results.py --port COM3 --timeout 60
```

This will save results to the [results/](../results/) folder as JSON files.

## Running Multiple Iterations

For statistical analysis, modify [src/main.cpp](../src/main.cpp):

```cpp
#define BENCHMARK_MODE
#define BENCHMARK_ITERATIONS 5  // Run 5 times
```

Then:
1. Flash the device
2. Wait for all iterations to complete (watch serial monitor)
3. Run the Python capture script to save results

## Configuration Options

### In src/main.cpp

- **BENCHMARK_MODE**: Enable benchmark mode (disables normal client/server)
- **BENCHMARK_ITERATIONS**: Number of iterations to run (default: 1)

### In Python script

```bash
--port PORT              # Serial port (default: auto-detect)
--baudrate BAUDRATE      # Serial baud rate (default: 115200)
--timeout TIMEOUT        # Timeout in seconds (default: 30)
--output OUTPUT_DIR      # Output directory (default: results)
```

## Analyzing Results

### View Raw Results

```bash
# List all JSON files
ls -la results/*.json

# View specific result
cat results/benchmark_ML-KEM-768_*.json | python -m json.tool
```

### Statistical Analysis (Python)

```python
import json
import statistics

# Load combined results
with open('results/benchmark_results_combined_*.json') as f:
    data = json.load(f)

# Analyze key generation times
keygen_times = [r['measurements']['key_generation']['execution_time_ms'] 
                for r in data['results']]

print(f"Key Generation Statistics:")
print(f"  Min: {min(keygen_times)} ms")
print(f"  Max: {max(keygen_times)} ms")
print(f"  Avg: {statistics.mean(keygen_times):.1f} ms")
print(f"  StdDev: {statistics.stdev(keygen_times):.1f} ms")
```

## Output Files

### Individual Results
- `benchmark_ML-KEM-768_20240331_120530_1.json`
- `benchmark_ML-KEM-768_20240331_120530_2.json`
- etc.

### Combined Results
- `benchmark_results_combined_20240331_120530.json`

## Troubleshooting

### Serial Port Not Found
```bash
# List available ports
python -m serial.tools.list_ports

# Manually specify port
python scripts/capture_benchmark_results.py --port COM3
```

### JSON Parse Errors
- Ensure serial monitor is not already open
- Check baud rate matches device setting (115200)
- Try --timeout 60 for slower connections

### No Data Captured
- Verify BENCHMARK_MODE is enabled
- Check serial port connection
- Try increasing timeout: `--timeout 60`

## File Structure

```
ML-KEM_Argon/
├── src/
│   ├── benchmark.h          # Benchmark function declarations
│   ├── benchmark.cpp        # Benchmark implementation
│   ├── main.cpp             # Main entry point (enable BENCHMARK_MODE here)
│   └── ...
├── results/
│   ├── README.md            # This file
│   ├── sample_result_*.json  # Example output
│   └── benchmark_*.json     # Your results
└── scripts/
    └── capture_benchmark_results.py  # Python capture script
```

## Example Workflow

```bash
# 1. Edit src/main.cpp and enable BENCHMARK_MODE
# 2. Compile
particle compile .

# 3. Flash to device
particle flash <device-id>

# 4. Wait a few seconds, then capture results
python scripts/capture_benchmark_results.py --timeout 30

# 5. View results
cat results/benchmark_*.json | python -m json.tool
```

## Expected Performance

### Typical Timing (ms)
| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| Key Gen   | 15-25     | 30-45     | 50-70      |
| Encaps    | 10-15     | 25-40     | 40-60      |
| Decaps    | 12-18     | 28-45     | 45-65      |
| **Total** | **40-60** | **85-130**| **135-195**|

> Note: Performance varies with system load and temperature

## Support

For issues or questions:
1. Check the serial monitor output for error messages
2. Verify BENCHMARK_MODE is uncommented in src/main.cpp
3. Ensure proper serial connection to device
4. Try different timeout values (30s, 60s, 120s)
