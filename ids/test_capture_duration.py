#!/usr/bin/env python3
"""
Debug script to test packet capture duration
This helps diagnose why capture might be ending early
"""

import time
import sys
import os
from datetime import datetime

try:
    from scapy.all import *
except ImportError:
    print("Error: scapy not installed")
    print("Install with: pip install scapy")
    sys.exit(1)

def test_capture_methods():
    """Test different capture methods to see which works best"""
    
    print("="*60)
    print("PACKET CAPTURE DURATION TEST")
    print("="*60)
    print(f"Start time: {datetime.now()}")
    print()
    
    # Test configuration
    test_duration = 10  # seconds
    packet_count = 0
    
    def count_packet(pkt):
        nonlocal packet_count
        packet_count += 1
    
    # Method 1: Using timeout parameter
    print(f"Method 1: Testing timeout={test_duration} parameter...")
    packet_count = 0
    start = time.time()
    
    try:
        sniff(timeout=test_duration, prn=count_packet, store=0)
    except KeyboardInterrupt:
        print("Interrupted!")
    
    elapsed1 = time.time() - start
    count1 = packet_count
    print(f"✓ Captured {count1} packets in {elapsed1:.2f} seconds")
    print(f"  Expected: {test_duration}s, Actual: {elapsed1:.2f}s")
    print()
    
    # Method 2: Using stop_filter
    print(f"Method 2: Testing stop_filter method...")
    packet_count = 0
    start = time.time()
    
    def stop_filter(pkt):
        return (time.time() - start) >= test_duration
    
    try:
        sniff(stop_filter=stop_filter, prn=count_packet, store=0)
    except KeyboardInterrupt:
        print("Interrupted!")
    
    elapsed2 = time.time() - start
    count2 = packet_count
    print(f"✓ Captured {count2} packets in {elapsed2:.2f} seconds")
    print(f"  Expected: {test_duration}s, Actual: {elapsed2:.2f}s")
    print()
    
    # Method 3: Using count parameter with timeout
    print(f"Method 3: Testing with packet count limit...")
    packet_count = 0
    start = time.time()
    
    try:
        # Capture up to 1000 packets or timeout
        sniff(count=1000, timeout=test_duration, prn=count_packet, store=0)
    except KeyboardInterrupt:
        print("Interrupted!")
    
    elapsed3 = time.time() - start
    count3 = packet_count
    print(f"✓ Captured {count3} packets in {elapsed3:.2f} seconds")
    print(f"  Expected: max {test_duration}s, Actual: {elapsed3:.2f}s")
    print()
    
    # Method 4: Manual timing with threading
    print(f"Method 4: Testing with manual thread control...")
    packet_count = 0
    start = time.time()
    
    import threading
    stop_event = threading.Event()
    
    def capture_thread():
        def should_stop(pkt):
            return stop_event.is_set()
        
        try:
            sniff(stop_filter=should_stop, prn=count_packet, store=0)
        except:
            pass
    
    thread = threading.Thread(target=capture_thread, daemon=True)
    thread.start()
    time.sleep(test_duration)
    stop_event.set()
    thread.join(timeout=1)
    
    elapsed4 = time.time() - start
    count4 = packet_count
    print(f"✓ Captured {count4} packets in {elapsed4:.2f} seconds")
    print(f"  Expected: {test_duration}s, Actual: {elapsed4:.2f}s")
    print()
    
    # Summary
    print("="*60)
    print("RESULTS SUMMARY")
    print("="*60)
    
    methods = [
        ("Timeout parameter", elapsed1, count1),
        ("Stop filter", elapsed2, count2),
        ("Count + timeout", elapsed3, count3),
        ("Thread control", elapsed4, count4)
    ]
    
    print(f"Target duration: {test_duration} seconds\n")
    
    for name, elapsed, count in methods:
        accuracy = 100 - abs(elapsed - test_duration) / test_duration * 100
        print(f"{name:20} | Duration: {elapsed:6.2f}s | Packets: {count:5} | Accuracy: {accuracy:.1f}%")
    
    print("\n" + "="*60)
    
    # Recommendations
    best_method = min(methods, key=lambda x: abs(x[1] - test_duration))
    print(f"✓ Best method for your system: {best_method[0]}")
    
    if all(count == 0 for _, _, count in methods):
        print("\n⚠️  WARNING: No packets captured!")
        print("Possible issues:")
        print("1. No network activity")
        print("2. Wrong permissions (need root/admin)")
        print("3. Firewall blocking")
        print("4. Wrong network interface")
    
    print("\nSystem Information:")
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Scapy: {conf.version}")
    
    # List interfaces
    print("\nAvailable interfaces:")
    try:
        from scapy.arch import get_if_list
        for iface in get_if_list():
            print(f"  - {iface}")
    except:
        print("  Could not list interfaces")

def test_specific_interface(interface=None, duration=10):
    """Test capture on a specific interface"""
    
    print(f"\nTesting interface: {interface or 'auto-detect'}")
    print(f"Duration: {duration} seconds")
    print("-"*40)
    
    packet_count = 0
    start_time = time.time()
    
    def packet_handler(pkt):
        nonlocal packet_count
        packet_count += 1
        if packet_count == 1:
            print(f"First packet captured at {time.time() - start_time:.2f}s")
        elif packet_count % 100 == 0:
            print(f"Captured {packet_count} packets...")
    
    def stop_capture(pkt):
        return (time.time() - start_time) >= duration
    
    try:
        print(f"Starting capture at {datetime.now().strftime('%H:%M:%S')}...")
        
        sniff(
            iface=interface,
            prn=packet_handler,
            stop_filter=stop_capture,
            store=0
        )
        
    except PermissionError:
        print("\n❌ Permission denied!")
        print("Run with administrator/root privileges:")
        print("  Windows: Run as Administrator")
        print("  Linux/Mac: sudo python test_capture.py")
        return
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return
    
    actual_duration = time.time() - start_time
    
    print(f"\nCapture stopped at {datetime.now().strftime('%H:%M:%S')}")
    print(f"Expected duration: {duration}s")
    print(f"Actual duration: {actual_duration:.2f}s")
    print(f"Total packets: {packet_count}")
    
    if packet_count > 0:
        print(f"Packet rate: {packet_count/actual_duration:.2f} packets/second")
    
    if abs(actual_duration - duration) > 1:
        print("\n⚠️  Duration mismatch detected!")
        print("Try the following fixes in your main script:")
        print("1. Use stop_filter instead of timeout")
        print("2. Add manual timing control")
        print("3. Check for blocking operations in packet handler")

if __name__ == "__main__":
    # Check permissions
    if os.name != 'nt' and os.geteuid() != 0:
        print("❌ This script requires root privileges")
        print("Run with: sudo python test_capture.py")
        sys.exit(1)
    
    print("Network Packet Capture Duration Test")
    print("This will test different capture methods for 10 seconds each")
    print("Total test time: ~40 seconds\n")
    
    response = input("Start tests? (y/n): ")
    if response.lower() != 'y':
        print("Exiting...")
        sys.exit(0)
    
    # Run comprehensive tests
    test_capture_methods()
    
    print("\n" + "="*60)
    print("TESTING SPECIFIC INTERFACE")
    print("="*60)
    
    # Optional: Test specific interface
    test_interface = input("\nTest specific interface? (press Enter to skip): ").strip()
    if test_interface:
        test_duration = input("Test duration in seconds (default 10): ").strip()
        test_duration = int(test_duration) if test_duration else 10
        test_specific_interface(test_interface, test_duration)
    
    print("\n✓ All tests complete!")