#!/usr/bin/env python3
"""
NIDS Quick Start - Simplified launcher with auto-configuration
Automatically detects network interface and runs basic monitoring
"""

import os
import sys
import time
import subprocess

def check_requirements():
    """Check if all requirements are installed"""
    required = ['scapy', 'pandas', 'matplotlib', 'plotly']
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print("❌ Missing required packages:")
        for m in missing:
            print(f"   - {m}")
        print("\n📦 Installing missing packages...")
        
        for package in missing:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        
        print("✅ All packages installed!")
        return True
    
    return True

def get_active_interface():
    """Auto-detect the active network interface"""
    try:
        from scapy.all import conf, get_if_list, get_if_addr
        
        # Try to find the interface with an IP address
        for iface in get_if_list():
            addr = get_if_addr(iface)
            if addr and addr != "0.0.0.0" and not addr.startswith("127."):
                return iface
        
        # Fallback to scapy's default
        return conf.iface
    except:
        return None

def run_quick_capture(duration=30):
    """Run a quick packet capture test"""
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   NIDS Quick Start - Auto Configuration   ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Check requirements
    if not check_requirements():
        return
    
    from scapy.all import sniff, IP, TCP, UDP
    import pandas as pd
    from datetime import datetime
    
    # Auto-detect interface
    interface = get_active_interface()
    print(f"\n🔍 Auto-detected interface: {interface}")
    
    # Packet storage
    packets_captured = []
    stats = {'tcp': 0, 'udp': 0, 'other': 0, 'total': 0}
    
    def process_packet(packet):
        """Simple packet processor"""
        stats['total'] += 1
        
        if IP in packet:
            pkt_info = {
                'time': datetime.now(),
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'proto': None,
                'size': len(packet)
            }
            
            if TCP in packet:
                stats['tcp'] += 1
                pkt_info['proto'] = 'TCP'
                pkt_info['sport'] = packet[TCP].sport
                pkt_info['dport'] = packet[TCP].dport
            elif UDP in packet:
                stats['udp'] += 1
                pkt_info['proto'] = 'UDP'
                pkt_info['sport'] = packet[UDP].sport
                pkt_info['dport'] = packet[UDP].dport
            else:
                stats['other'] += 1
                pkt_info['proto'] = 'Other'
            
            packets_captured.append(pkt_info)
    
    print(f"⏱  Starting {duration}-second capture...")
    print(f"📍 Interface: {interface}")
    print("\n" + "-"*40)
    
    start_time = time.time()
    
    def stop_filter(pkt):
        elapsed = time.time() - start_time
        if int(elapsed) % 5 == 0 and int(elapsed) > 0:
            print(f"\r⏱  Time: {int(elapsed)}/{duration}s | Packets: {stats['total']} | TCP: {stats['tcp']} | UDP: {stats['udp']}", end='', flush=True)
        return elapsed >= duration
    
    try:
        # Start capture
        sniff(
            iface=interface,
            prn=process_packet,
            stop_filter=stop_filter,
            store=0
        )
        
        print("\n" + "-"*40)
        print("\n✅ Capture complete!\n")
        
        # Show results
        print("📊 CAPTURE STATISTICS")
        print("="*40)
        print(f"Total Packets: {stats['total']}")
        print(f"TCP Packets: {stats['tcp']}")
        print(f"UDP Packets: {stats['udp']}")
        print(f"Other Packets: {stats['other']}")
        
        if packets_captured:
            df = pd.DataFrame(packets_captured)
            
            print("\n🔝 TOP TALKERS")
            print("="*40)
            top_src = df['src'].value_counts().head(5)
            for ip, count in top_src.items():
                print(f"{ip:20} : {count} packets")
            
            print("\n🎯 TOP DESTINATIONS")
            print("="*40)
            top_dst = df['dst'].value_counts().head(5)
            for ip, count in top_dst.items():
                print(f"{ip:20} : {count} packets")
            
            if 'dport' in df.columns:
                print("\n🔌 TOP PORTS")
                print("="*40)
                top_ports = df['dport'].value_counts().head(5)
                for port, count in top_ports.items():
                    service = {
                        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 
                        53: 'DNS', 21: 'FTP', 25: 'SMTP'
                    }.get(port, 'Unknown')
                    print(f"Port {port:5} ({service:10}) : {count} connections")
            
            # Save basic report
            report_file = f"quick_capture_{datetime.now():%Y%m%d_%H%M%S}.txt"
            with open(report_file, 'w') as f:
                f.write("NIDS Quick Capture Report\n")
                f.write("="*40 + "\n")
                f.write(f"Duration: {duration} seconds\n")
                f.write(f"Interface: {interface}\n")
                f.write(f"Total Packets: {stats['total']}\n")
                f.write(f"TCP: {stats['tcp']}, UDP: {stats['udp']}, Other: {stats['other']}\n")
            
            print(f"\n💾 Report saved to: {report_file}")
            
        else:
            print("\n⚠️  No packets captured. Try:")
            print("  1. Generate some network traffic (browse web)")
            print("  2. Check if correct interface is selected")
            print("  3. Verify firewall settings")
        
    except PermissionError:
        print("\n❌ Permission denied!")
        print("\nPlease run with elevated privileges:")
        if os.name == 'nt':
            print("  Windows: Right-click and 'Run as Administrator'")
        else:
            print("  Linux/Mac: sudo python quickstart.py")
    except KeyboardInterrupt:
        print("\n\n⛔ Capture interrupted by user")
        print(f"Captured {stats['total']} packets before stopping")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main function"""
    
    # Check permissions first
    if os.name != 'nt' and os.geteuid() != 0:
        print("❌ This script requires root privileges")
        print("Please run with: sudo python quickstart.py")
        sys.exit(1)
    
    print("Welcome to NIDS Quick Start!")
    print("This will run a quick 30-second network capture test\n")
    
    # Options
    print("Options:")
    print("1. Quick test (30 seconds)")
    print("2. Standard test (60 seconds)")
    print("3. Extended test (120 seconds)")
    print("4. Custom duration")
    
    choice = input("\nSelect option (1-4, default=1): ").strip() or "1"
    
    if choice == "1":
        duration = 30
    elif choice == "2":
        duration = 60
    elif choice == "3":
        duration = 120
    elif choice == "4":
        duration = input("Enter duration in seconds: ").strip()
        try:
            duration = int(duration)
        except:
            print("Invalid duration, using 30 seconds")
            duration = 30
    else:
        duration = 30
    
    print(f"\n🚀 Starting {duration}-second capture test...")
    print("Press Ctrl+C to stop early\n")
    
    run_quick_capture(duration)
    
    print("\n" + "="*50)
    print("✨ Quick test complete!")
    print("\nNext steps:")
    print("1. Run the full NIDS: python nids.py")
    print("2. Test detection: python test_nids.py <target_ip>")
    print("3. Read documentation: see nids_documentation.md")
    print("="*50)

if __name__ == "__main__":
    main()