#!/usr/bin/env python3
"""
Quick test script to verify packet capture works on your system
"""

import sys
import os

def test_permissions():
    """Test if we have the required permissions"""
    if os.name != 'nt' and os.geteuid() != 0:
        print("❌ ERROR: Need root privileges on Linux/Mac")
        print("Run with: sudo python3 test_packet_capture.py")
        return False
    return True

def test_scapy_import():
    """Test if scapy can be imported and basic functions work"""
    try:
        from scapy.all import sniff, get_if_list, conf
        print("✅ Scapy imported successfully")
        
        # List available interfaces
        interfaces = get_if_list()
        print(f"📡 Available interfaces: {interfaces}")
        
        return True, interfaces
    except ImportError:
        print("❌ Scapy not installed. Install with: pip install scapy")
        return False, []
    except Exception as e:
        print(f"❌ Scapy error: {e}")
        return False, []

def test_basic_capture(interface=None, duration=5):
    """Test basic packet capture for a few seconds"""
    try:
        from scapy.all import sniff
        
        print(f"🚀 Testing packet capture for {duration} seconds...")
        print("💡 Generate some network traffic (browse web, ping, etc.)")
        
        packet_count = 0
        
        def count_packets(packet):
            nonlocal packet_count
            packet_count += 1
            if packet_count % 10 == 0:  # Print every 10th packet
                print(f"📦 Captured {packet_count} packets...", end='\r')
        
        # Capture packets
        sniff(iface=interface, prn=count_packets, timeout=duration, store=False)
        
        print(f"\n✅ Successfully captured {packet_count} packets!")
        
        if packet_count == 0:
            print("⚠️  WARNING: No packets captured. Possible issues:")
            print("   - Wrong interface")
            print("   - No network activity")
            print("   - Firewall blocking")
            print("   - Permission issues")
        
        return packet_count > 0
        
    except Exception as e:
        print(f"❌ Capture failed: {e}")
        return False

def main():
    print("🔍 Testing Network Packet Capture Capability")
    print("=" * 50)
    
    # Test 1: Permissions
    if not test_permissions():
        return
    
    # Test 2: Scapy import and interface detection
    scapy_ok, interfaces = test_scapy_import()
    if not scapy_ok:
        return
    
    # Test 3: Basic packet capture
    # Try with default interface first
    print(f"\n🧪 Test 1: Capture with default interface")
    success = test_basic_capture(interface=None, duration=5)
    
    # If that fails, try specific interfaces
    if not success and interfaces:
        for iface in interfaces[:2]:  # Try first 2 interfaces
            print(f"\n🧪 Test 2: Capture with interface '{iface}'")
            success = test_basic_capture(interface=iface, duration=5)
            if success:
                break
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 RESULT: Packet capture works on your system!")
        print("✅ The NIDS script should work correctly")
    else:
        print("❌ RESULT: Packet capture issues detected")
        print("🔧 The NIDS script may need configuration adjustments")
    
    print("\n💡 Tips for the main NIDS script:")
    print("1. Run with admin/root privileges")
    print("2. Specify the correct interface manually if auto-detection fails")
    print("3. Generate network traffic during capture")
    print("4. Check firewall settings if no packets are captured")

if __name__ == "__main__":
    main()