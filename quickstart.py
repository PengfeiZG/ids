#!/usr/bin/env python3
"""
NIDS Quick Start - Simplified launcher with auto-configuration
Works with the main Network Connection Monitor (no special privileges required)
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

def check_requirements():
    """Check if all requirements are installed"""
    required = ['psutil']
    optional = ['openai', 'pandas', 'matplotlib']
    missing_required = []
    missing_optional = []
    
    # Check required packages
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing_required.append(module)
    
    # Check optional packages
    for module in optional:
        try:
            __import__(module)
        except ImportError:
            missing_optional.append(module)
    
    if missing_required:
        print("❌ Missing REQUIRED packages:")
        for m in missing_required:
            print(f"   - {m}")
        print("\n📦 Installing required packages...")
        
        for package in missing_required:
            print(f"Installing {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            except:
                print(f"Failed to install {package}. Please install manually: pip install {package}")
                return False
        
        print("✅ Required packages installed!")
    
    if missing_optional:
        print("\n⚠️ Optional packages not installed (some features disabled):")
        for m in missing_optional:
            print(f"   - {m}")
        print("Install with: pip install " + " ".join(missing_optional))
    
    return True

def run_quick_monitor(duration=30):
    """Run a quick network monitoring session"""
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   NIDS Quick Start - Network Monitor     ║
    ║   No special privileges required!         ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Check requirements
    if not check_requirements():
        return
    
    import psutil
    
    # Settings
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6666, 6667, 31337]
    port_names = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        4444: 'Metasploit', 5900: 'VNC', 6666: 'IRC-Bot',
        6667: 'IRC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        31337: 'BackOrifice'
    }
    
    # Data storage
    connections_history = []
    unique_source_ips = set()
    unique_dest_ips = set()
    port_activity = defaultdict(int)
    alerts = []
    ip_connection_count = defaultdict(int)
    
    print(f"⏱️  Starting {duration}-second monitoring session...")
    print(f"📊 Monitoring all network connections")
    print("\n" + "-"*50)
    
    start_time = time.time()
    last_update = 0
    
    try:
        while time.time() - start_time < duration:
            # Get current connections
            current_connections = psutil.net_connections(kind='inet')
            
            for conn in current_connections:
                # Extract connection info
                if conn.laddr:
                    source_ip = conn.laddr.ip
                    source_port = conn.laddr.port
                    unique_source_ips.add(source_ip)
                    port_activity[source_port] += 1
                else:
                    source_ip = None
                    source_port = None
                
                if conn.raddr:
                    dest_ip = conn.raddr.ip
                    dest_port = conn.raddr.port
                    unique_dest_ips.add(dest_ip)
                    port_activity[dest_port] += 1
                    ip_connection_count[dest_ip] += 1
                    
                    # Check for suspicious activity
                    if dest_port in suspicious_ports:
                        alert = {
                            'time': datetime.now(),
                            'type': 'SUSPICIOUS_PORT',
                            'message': f"Connection to suspicious port {dest_port} ({port_names.get(dest_port, 'Unknown')})",
                            'source': f"{source_ip}:{source_port}",
                            'dest': f"{dest_ip}:{dest_port}"
                        }
                        alerts.append(alert)
                else:
                    dest_ip = None
                    dest_port = None
                
                # Get process info
                try:
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    else:
                        process_name = "Unknown"
                except:
                    process_name = "Unknown"
                
                # Store connection
                conn_info = {
                    'time': datetime.now(),
                    'source_ip': source_ip,
                    'source_port': source_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'status': conn.status,
                    'process': process_name
                }
                connections_history.append(conn_info)
            
            # Check for high connection volumes
            for ip, count in ip_connection_count.items():
                if count > 50:  # Threshold
                    alert = {
                        'time': datetime.now(),
                        'type': 'HIGH_CONNECTIONS',
                        'message': f"High connection count from {ip}: {count} connections",
                        'source': ip,
                        'dest': None
                    }
                    if alert not in alerts:  # Avoid duplicates
                        alerts.append(alert)
            
            # Update display every 2 seconds
            elapsed = int(time.time() - start_time)
            if elapsed > last_update and elapsed % 2 == 0:
                last_update = elapsed
                print(f"\r⏱️ Time: {elapsed}/{duration}s | "
                      f"Connections: {len(connections_history)} | "
                      f"Unique IPs: {len(unique_source_ips) + len(unique_dest_ips)} | "
                      f"Alerts: {len(alerts)}", end='', flush=True)
            
            # Sleep briefly to avoid CPU overuse
            time.sleep(0.5)
        
        print("\n" + "-"*50)
        print("\n✅ Monitoring complete!\n")
        
        # Get network IO stats
        net_io = psutil.net_io_counters()
        
        # Show results
        print("📊 MONITORING STATISTICS")
        print("="*50)
        print(f"Total Connections Observed: {len(connections_history)}")
        print(f"Unique Source IPs: {len(unique_source_ips)}")
        print(f"Unique Destination IPs: {len(unique_dest_ips)}")
        print(f"Active Ports: {len(port_activity)}")
        print(f"Security Alerts: {len(alerts)}")
        print(f"Data Sent: {net_io.bytes_sent / (1024*1024):.2f} MB")
        print(f"Data Received: {net_io.bytes_recv / (1024*1024):.2f} MB")
        
        if unique_dest_ips:
            print("\n🎯 TOP DESTINATION IPs")
            print("="*50)
            dest_counter = Counter([c['dest_ip'] for c in connections_history if c['dest_ip']])
            for ip, count in dest_counter.most_common(5):
                print(f"{ip:20} : {count} connections")
        
        if port_activity:
            print("\n🔌 TOP PORTS")
            print("="*50)
            for port, count in sorted(port_activity.items(), key=lambda x: x[1], reverse=True)[:5]:
                service = port_names.get(port, 'Unknown')
                suspicious = " ⚠️ SUSPICIOUS" if port in suspicious_ports else ""
                print(f"Port {port:5} ({service:15}) : {count} connections{suspicious}")
        
        if alerts:
            print("\n🚨 SECURITY ALERTS")
            print("="*50)
            for alert in alerts[:10]:  # Show first 10 alerts
                print(f"[{alert['time'].strftime('%H:%M:%S')}] {alert['type']}")
                print(f"  {alert['message']}")
        
        # Process connections to find top processes
        process_counter = Counter([c['process'] for c in connections_history if c['process'] != "Unknown"])
        if process_counter:
            print("\n📱 TOP PROCESSES")
            print("="*50)
            for process, count in process_counter.most_common(5):
                print(f"{process:20} : {count} connections")
        
        # Save report
        report_file = f"quick_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write("NIDS Quick Monitor Report\n")
            f.write("="*50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration} seconds\n")
            f.write(f"\nSTATISTICS\n")
            f.write("-"*30 + "\n")
            f.write(f"Total Connections: {len(connections_history)}\n")
            f.write(f"Unique Source IPs: {len(unique_source_ips)}\n")
            f.write(f"Unique Destination IPs: {len(unique_dest_ips)}\n")
            f.write(f"Active Ports: {len(port_activity)}\n")
            f.write(f"Security Alerts: {len(alerts)}\n")
            f.write(f"Data Sent: {net_io.bytes_sent / (1024*1024):.2f} MB\n")
            f.write(f"Data Received: {net_io.bytes_recv / (1024*1024):.2f} MB\n")
            
            if unique_source_ips:
                f.write(f"\nSOURCE IPs\n")
                f.write("-"*30 + "\n")
                for ip in sorted(unique_source_ips):
                    f.write(f"{ip}\n")
            
            if unique_dest_ips:
                f.write(f"\nDESTINATION IPs\n")
                f.write("-"*30 + "\n")
                for ip in sorted(unique_dest_ips):
                    f.write(f"{ip}\n")
            
            if alerts:
                f.write(f"\nSECURITY ALERTS\n")
                f.write("-"*30 + "\n")
                for alert in alerts:
                    f.write(f"[{alert['time'].strftime('%Y-%m-%d %H:%M:%S')}] {alert['type']}\n")
                    f.write(f"  {alert['message']}\n")
        
        print(f"\n💾 Report saved to: {report_file}")
        
        # Save JSON for potential import
        json_file = f"quick_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        export_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'duration': duration,
                'version': '1.0'
            },
            'statistics': {
                'total_connections': len(connections_history),
                'unique_source_ips': list(unique_source_ips),
                'unique_dest_ips': list(unique_dest_ips),
                'alerts_count': len(alerts)
            },
            'alerts': [
                {
                    'time': a['time'].isoformat(),
                    'type': a['type'],
                    'message': a['message']
                }
                for a in alerts
            ]
        }
        
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"📄 JSON data saved to: {json_file}")
        
    except KeyboardInterrupt:
        print("\n\n⛔ Monitoring interrupted by user")
        print(f"Captured {len(connections_history)} connections before stopping")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main function"""
    
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║     Network Connection Monitor - Quick Start      ║
    ║                                                   ║
    ║  ✅ No special privileges required                ║
    ║  ✅ Works on all platforms                        ║
    ║  ✅ Compatible with main NIDS application         ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    print("This will run a quick network monitoring test")
    print("No admin/root privileges needed!\n")
    
    # Options
    print("Select monitoring duration:")
    print("1. Quick test (30 seconds)")
    print("2. Standard test (60 seconds)")
    print("3. Extended test (2 minutes)")
    print("4. Long test (5 minutes)")
    print("5. Custom duration")
    
    choice = input("\nSelect option (1-5, default=1): ").strip() or "1"
    
    if choice == "1":
        duration = 30
    elif choice == "2":
        duration = 60
    elif choice == "3":
        duration = 120
    elif choice == "4":
        duration = 300
    elif choice == "5":
        duration = input("Enter duration in seconds: ").strip()
        try:
            duration = int(duration)
            if duration < 5:
                print("Minimum duration is 5 seconds")
                duration = 5
            elif duration > 3600:
                print("Maximum duration is 1 hour (3600 seconds)")
                duration = 3600
        except:
            print("Invalid duration, using 30 seconds")
            duration = 30
    else:
        duration = 30
    
    print(f"\n🚀 Starting {duration}-second monitoring session...")
    print("Press Ctrl+C to stop early\n")
    
    run_quick_monitor(duration)
    
    print("\n" + "="*60)
    print("✨ Quick monitoring complete!")
    print("\nNext steps:")
    print("1. Run the full GUI application: python nids_enhanced_monitoring.py")
    print("2. Review the generated report files")
    print("3. Configure settings for continuous monitoring")
    print("\n💡 Tips:")
    print("• The GUI version provides real-time visualization")
    print("• You can set up AI analysis for threat detection")
    print("• Export detailed reports for security analysis")
    print("="*60)

if __name__ == "__main__":
    main()