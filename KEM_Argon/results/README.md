# ML-KEM Benchmark Results

This folder contains the performance measurements for ML-KEM key generation, encapsulation, and decapsulation operations on the Particle Argon.

## File Structure

- `benchmark_*.json` - Individual benchmark measurements
- `benchmark_results_combined_*.json` - Combined results from multiple runs

## Running Benchmarks

### Method 1: Direct Benchmark Mode (Particle Argon)

Uncomment `#define BENCHMARK_MODE` in `src/main.cpp` and flash the device:

```cpp
#define BENCHMARK_MODE          // Run performance benchmarks
//#define BENCHMARK_ITERATIONS 5  // Number of iterations for statistical analysis
```

Then compile and flash:
```bash
particle compile .
particle flash <device-id>
```

### Method 2: Multiple Iterations

For statistical analysis across multiple runs:

```cpp
#define BENCHMARK_MODE          // Run performance benchmarks
#define BENCHMARK_ITERATIONS 5  // Run 5 times
```

### Method 3: Capture from Serial Port

After the device is flashing and running benchmarks, use the Python script to capture results:

```bash
# Auto-detect port
python scripts/capture_benchmark_results.py

# Specify port manually
python scripts/capture_benchmark_results.py --port COM3 --baudrate 115200

# Custom timeout and output directory
python scripts/capture_benchmark_results.py --port COM3 --timeout 60 --output results
```

## JSON Format

Each benchmark result contains:

```json
{
  "variant": "ML-KEM-768",
  "timestamp_ms": 12345,
  "measurements": {
    "key_generation": {
      "execution_time_ms": 45,
      "heap_used_bytes": 256,
      "max_heap_bytes": 65536
    },
    "encapsulation": {
      "execution_time_ms": 38,
      "heap_used_bytes": 128,
      "max_heap_bytes": 65536
    },
    "decapsulation": {
      "execution_time_ms": 42,
      "heap_used_bytes": 128,
      "max_heap_bytes": 65536
    },
    "total_process": {
      "execution_time_ms": 125,
      "heap_used_bytes": 512,
      "max_heap_bytes": 65536
    }
  }
}
```

## Metrics Explained

- **execution_time_ms**: Time taken for the operation in milliseconds
- **heap_used_bytes**: Approximate heap memory used during the operation
- **max_heap_bytes**: Maximum available heap for the operation

## Expected Performance

### ML-KEM-512
- Key Generation: ~15-25 ms
- Encapsulation: ~10-15 ms
- Decapsulation: ~12-18 ms
- Total: ~40-60 ms

### ML-KEM-768
- Key Generation: ~30-45 ms
- Encapsulation: ~25-40 ms
- Decapsulation: ~28-45 ms
- Total: ~85-130 ms

### ML-KEM-1024
- Key Generation: ~50-70 ms
- Encapsulation: ~40-60 ms
- Decapsulation: ~45-65 ms
- Total: ~135-195 ms

> Note: Actual performance will vary based on system load and other factors.

## Analyzing Results

Use Python to analyze multiple benchmark results:

```python
import json
import statistics

# Load a combined results file
with open('results/benchmark_results_combined_*.json', 'r') as f:
    data = json.load(f)

# Extract keygen times
keygen_times = [r['measurements']['key_generation']['execution_time_ms'] 
                for r in data['results']]

# Calculate statistics
print(f"Keygen - Min: {min(keygen_times)}ms, Max: {max(keygen_times)}ms, Avg: {statistics.mean(keygen_times):.1f}ms")
```
