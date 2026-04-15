#!/usr/bin/env python3
"""
ML-KEM Benchmark Result Capture and Analysis Script
Captures benchmark output from Particle Argon serial monitor and saves as JSON
"""

import serial
import json
import re
import sys
from datetime import datetime
from pathlib import Path

class BenchmarkCapture:
    def __init__(self, port, baudrate=115200, timeout=120):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None
        self.json_data = None
        
    def connect(self):
        """Connect to serial port"""
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
            print(f"✓ Connected to {self.port} at {self.baudrate} baud")
            return True
        except Exception as e:
            print(f"✗ Failed to connect to {self.port}: {e}")
            return False
    
    def read_until_json(self, marker_start="========== JSON Results"):
        """Read serial output until JSON is found"""
        print(f"\nWaiting for benchmark results (up to {self.timeout}s)...")
        
        buffer = ""
        start_time = datetime.now()
        json_started = False
        json_buffer = ""
        brace_count = 0
        
        while (datetime.now() - start_time).total_seconds() < self.timeout:
            try:
                if self.ser.in_waiting:
                    chunk = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                    buffer += chunk
                    print(chunk, end='')
                    
                    if not json_started and marker_start in buffer:
                        print("\n\n✓ Found JSON marker, capturing JSON data...\n")
                        json_started = True
                        # Find the first '{' after marker
                        idx = buffer.rfind('{')
                        if idx != -1:
                            json_buffer = buffer[idx:]
                            brace_count = 1
                    elif json_started:
                        # Count braces to find complete JSON
                        for char in chunk:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                            json_buffer += char
                            
                            if brace_count == 0 and len(json_buffer) > 10:
                                print("\n✓ Complete JSON received!")
                                return json_buffer.strip()
                else:
                    import time
                    time.sleep(0.1)
                    
            except Exception as e:
                print(f"Error reading serial: {e}")
                return None
        
        print(f"✗ Timeout waiting for benchmark results")
        return None
    
    def parse_json(self, json_str):
        """Parse JSON string"""
        try:
            self.json_data = json.loads(json_str)
            print("✓ JSON parsed successfully")
            return True
        except json.JSONDecodeError as e:
            print(f"✗ Failed to parse JSON: {e}")
            return False
    
    def save_json(self, filename):
        """Save JSON to file"""
        if not self.json_data:
            print("✗ No JSON data to save")
            return False
        
        try:
            filepath = Path(filename)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(self.json_data, f, indent=2)
            
            print(f"✓ Results saved to: {filepath}")
            return True
        except Exception as e:
            print(f"✗ Failed to save JSON: {e}")
            return False
    
    def print_summary(self):
        """Print benchmark summary"""
        if not self.json_data:
            print("✗ No JSON data to summarize")
            return
        
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        if 'metadata' in self.json_data:
            meta = self.json_data['metadata']
            print(f"\nDevice:         {meta.get('device', 'Unknown')}")
            print(f"Firmware:       {meta.get('firmware', 'Unknown')}")
            print(f"Timestamp:      {meta.get('timestamp', 'Unknown')}")
            print(f"Total Results:  {meta.get('total_results', 0)}")
            print(f"Free Heap:      {meta.get('free_heap_bytes', 0)} bytes")
            print(f"Total Heap:     {meta.get('total_heap_bytes', 0)} bytes")
        
        if 'summary' in self.json_data:
            summary = self.json_data['summary']
            print("\n--- Performance Metrics (ML-KEM-512) ---")
            
            print(f"KeyGen:")
            print(f"  Avg Time:    {summary.get('ml_kem_512_keygen_avg_milliseconds', 0):.3f} ms")
            print(f"  Microseconds: {summary.get('ml_kem_512_keygen_avg_microseconds', 0)} μs")
            
            print(f"Encapsulation:")
            print(f"  Avg Time:    {summary.get('ml_kem_512_encap_avg_milliseconds', 0):.3f} ms")
            print(f"  Microseconds: {summary.get('ml_kem_512_encap_avg_microseconds', 0)} μs")
            
            print(f"Decapsulation:")
            print(f"  Avg Time:    {summary.get('ml_kem_512_decap_avg_milliseconds', 0):.3f} ms")
            print(f"  Microseconds: {summary.get('ml_kem_512_decap_avg_microseconds', 0)} μs")
            
            print(f"\nFull Key Exchange:")
            print(f"  Total Time:  {summary.get('ml_kem_512_full_exchange_milliseconds', 0):.3f} ms")
            print(f"               {summary.get('ml_kem_512_full_exchange_seconds', 0):.6f} seconds")
            
            print(f"\nMemory Usage:")
            print(f"  Avg Heap:    {summary.get('average_heap_usage_bytes', 0)} bytes")
            print(f"  Max Stack:   {summary.get('max_stack_usage_bytes', 0)} bytes")
        
        print("\n" + "="*60 + "\n")
    
    def close(self):
        """Close serial connection"""
        if self.ser:
            self.ser.close()
            print("✓ Serial connection closed")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Capture and save ML-KEM benchmark results from Particle Argon'
    )
    parser.add_argument('port', nargs='?', default='COM6', 
                       help='Serial port (default: COM6)')
    parser.add_argument('--output', '-o', default='benchmark_results.json',
                       help='Output JSON file (default: benchmark_results.json)')
    parser.add_argument('--timeout', '-t', type=int, default=300,
                       help='Timeout in seconds (default: 300)')
    parser.add_argument('--baudrate', '-b', type=int, default=115200,
                       help='Baud rate (default: 115200)')
    
    args = parser.parse_args()
    
    print("╔════════════════════════════════════════════════╗")
    print("║  ML-KEM Benchmark Result Capture & Analysis  ║")
    print("║         Particle Argon Performance Test        ║")
    print("╚════════════════════════════════════════════════╝\n")
    
    capture = BenchmarkCapture(args.port, args.baudrate, args.timeout)
    
    if not capture.connect():
        sys.exit(1)
    
    json_str = capture.read_until_json()
    capture.close()
    
    if not json_str:
        print("\n✗ Failed to capture benchmark results")
        sys.exit(1)
    
    if not capture.parse_json(json_str):
        sys.exit(1)
    
    if not capture.save_json(args.output):
        sys.exit(1)
    
    capture.print_summary()
    print(f"✓ Benchmark analysis complete!")


if __name__ == '__main__':
    main()
