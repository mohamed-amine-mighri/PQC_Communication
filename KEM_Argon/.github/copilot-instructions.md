<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->
- [x] Project requirements clarified: Particle Argon, ML-KEM, MQTT, UART, WiFi, RGB LED
- [x] Project scaffolded in ML-KEM_Argon directory
- [x] Customize the project: Copy and adapt code from ESP32 version
- [x] Install required extensions: None needed for Particle OS
- [x] Compile the project: Use Particle Workbench or CLI
- [x] Create and run task: Add build/flash task if needed
- [x] Launch the project: Flash to Argon and run
- [x] Ensure documentation is complete: README.md and copilot-instructions.md
- [x] **NEW**: Benchmarking system implemented for performance measurements

## Execution Guidelines
- Use Particle Device OS APIs
- Remove ESP-IDF/FreeRTOS dependencies
- Map pins to Argon (D0-D8, A0-A5)
- Use Particle WiFi, MQTT, Serial, RGB APIs
- Use C++ STL for queue abstraction
- Keep communication concise

## Benchmarking System (NEW)
A complete benchmarking system has been implemented to measure ML-KEM performance:

### Features
- Measures execution time and memory usage for:
  - Key generation (`mlkem_keypair`)
  - Encapsulation (`mlkem_enc`)
  - Decapsulation (`mlkem_dec`)
  - Total process time
- Saves results in JSON format to `results/` folder
- Supports single run or multiple iterations for statistical analysis
- Python capture script to collect results from serial port

### Files Created
- `src/benchmark.h` - Benchmark function declarations
- `src/benchmark.cpp` - Benchmark implementation with timing/memory measurement
- `scripts/capture_benchmark_results.py` - Python script to capture and save JSON results
- `BENCHMARK_GUIDE.md` - Complete usage documentation
- `results/README.md` - Results folder documentation with format specification

### Usage
1. Enable in `src/main.cpp`:
   ```cpp
   #define BENCHMARK_MODE
   // #define BENCHMARK_ITERATIONS 5  // Optional: for statistical analysis
   ```
2. Flash device: `particle compile . && particle flash <device-id>`
3. Capture results: `python scripts/capture_benchmark_results.py`
4. Results saved to `results/benchmark_*.json` in JSON format

### JSON Output Format
Results include variant name, timestamp, and measurements for each operation with:
- execution_time_ms (execution duration)
- heap_used_bytes (memory used)
- max_heap_bytes (available heap)
