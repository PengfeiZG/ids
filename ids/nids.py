#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
A Python-based IDS for detecting suspicious network activity
Author: Network Security Tool
Version: 1.0
"""

import os
import sys
import time
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any
import threading
import queue

# Core dependencies
import pandas as pd
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest

# Visualization
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# For AI summarization (optional)
try:
    import openai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("OpenAI not installed. AI summarization will be disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nids.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkIDS:
    """Main Network Intrusion Detection System class"""
    
    def __init__(self, interface=None, pcap_file=None):
        """
        Initialize the NIDS
        
        Args:
            interface: Network interface to monitor (e.g., 'Wi-Fi', 'eth0')
            pcap_file: Optional PCAP file for offline analysis
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.packets = []
        self.alerts = []
        self.packet_queue = queue.Queue()
        self.running = False
        
        # Detection thresholds
        self.thresholds = {
            'syn_flood_threshold': 100,  # SYN packets per second
            'port_scan_threshold': 20,   # Different ports accessed
            'packet_rate_threshold': 1000,  # Packets per second from single IP
            'failed_connection_threshold': 10,  # Failed connections in 60 seconds
            'unusual_port_threshold': 5  # Connections to unusual ports
        }
        
        # Known suspicious ports
        self.suspicious_ports = {
            23: 'Telnet',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'MSSQL',
            3389: 'RDP',
            4444: 'Metasploit',
            5900: 'VNC',
            6666: 'IRC Bot',
            6667: 'IRC',
            31337: 'Back Orifice'
        }
        
        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0,
            'alerts_generated': 0
        }
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            'syn': 0, 'syn_ack': 0, 'ack': 0, 'fin': 0,
            'rst': 0, 'packets': 0, 'bytes': 0,
            'ports': set(), 'start_time': None
        })
        
        logger.info("NIDS initialized successfully")
    
    def packet_callback(self, packet):
        """Process captured packets"""
        try:
            self.packet_queue.put(packet)
            self.stats['total_packets'] += 1
            
            # Extract packet info
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.packets.append(packet_info)
                self.analyze_packet(packet_info)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        info = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload_size': 0
        }
        
        try:
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['flags'] = packet[TCP].flags
                    info['payload_size'] = len(packet[TCP].payload)
                    self.stats['tcp_packets'] += 1
                    
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                    info['payload_size'] = len(packet[UDP].payload)
                    self.stats['udp_packets'] += 1
                    
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['icmp_type'] = packet[ICMP].type
                    self.stats['icmp_packets'] += 1
                    
                return info
                
        except Exception as e:
            logger.debug(f"Could not extract packet info: {e}")
            
        return None
    
    def analyze_packet(self, packet_info: Dict):
        """Analyze packet for suspicious activity"""
        if not packet_info['src_ip']:
            return
            
        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        
        # Update connection tracking
        conn_key = f"{src_ip}->{packet_info['dst_ip']}"
        conn = self.connections[conn_key]
        conn['packets'] += 1
        conn['bytes'] += packet_info['size']
        
        if not conn['start_time']:
            conn['start_time'] = packet_info['timestamp']
            
        if dst_port:
            conn['ports'].add(dst_port)
            
        # Check for TCP flags
        if packet_info['protocol'] == 'TCP' and packet_info['flags']:
            flags = packet_info['flags']
            if 'S' in str(flags) and 'A' not in str(flags):
                conn['syn'] += 1
            elif 'S' in str(flags) and 'A' in str(flags):
                conn['syn_ack'] += 1
            elif 'F' in str(flags):
                conn['fin'] += 1
            elif 'R' in str(flags):
                conn['rst'] += 1
                
        # Detect anomalies
        self.detect_syn_flood(src_ip, conn)
        self.detect_port_scan(src_ip, conn)
        self.detect_suspicious_ports(packet_info)
        self.detect_high_packet_rate(src_ip, conn)
    
    def detect_syn_flood(self, src_ip: str, conn: Dict):
        """Detect potential SYN flood attacks"""
        if conn['syn'] > self.thresholds['syn_flood_threshold']:
            if conn['syn_ack'] < conn['syn'] * 0.1:  # Less than 10% SYN-ACK responses
                self.create_alert(
                    'SYN_FLOOD',
                    f"Possible SYN flood from {src_ip}",
                    {
                        'source_ip': src_ip,
                        'syn_count': conn['syn'],
                        'syn_ack_count': conn['syn_ack']
                    }
                )
    
    def detect_port_scan(self, src_ip: str, conn: Dict):
        """Detect potential port scanning"""
        if len(conn['ports']) > self.thresholds['port_scan_threshold']:
            self.create_alert(
                'PORT_SCAN',
                f"Possible port scan from {src_ip}",
                {
                    'source_ip': src_ip,
                    'ports_scanned': list(conn['ports']),
                    'port_count': len(conn['ports'])
                }
            )
    
    def detect_suspicious_ports(self, packet_info: Dict):
        """Detect connections to suspicious ports"""
        dst_port = packet_info['dst_port']
        if dst_port in self.suspicious_ports:
            self.create_alert(
                'SUSPICIOUS_PORT',
                f"Connection to suspicious port {dst_port} ({self.suspicious_ports[dst_port]})",
                {
                    'source_ip': packet_info['src_ip'],
                    'destination_ip': packet_info['dst_ip'],
                    'port': dst_port,
                    'service': self.suspicious_ports[dst_port]
                }
            )
    
    def detect_high_packet_rate(self, src_ip: str, conn: Dict):
        """Detect unusually high packet rates"""
        if conn['start_time']:
            elapsed = (datetime.now() - conn['start_time']).total_seconds()
            if elapsed > 0:
                rate = conn['packets'] / elapsed
                if rate > self.thresholds['packet_rate_threshold']:
                    self.create_alert(
                        'HIGH_PACKET_RATE',
                        f"Unusually high packet rate from {src_ip}",
                        {
                            'source_ip': src_ip,
                            'packet_rate': rate,
                            'total_packets': conn['packets'],
                            'total_bytes': conn['bytes']
                        }
                    )
    
    def create_alert(self, alert_type: str, description: str, details: Dict):
        """Create and log an alert"""
        alert = {
            'timestamp': datetime.now(),
            'type': alert_type,
            'severity': self.get_severity(alert_type),
            'description': description,
            'details': details
        }
        
        # Avoid duplicate alerts
        if not self.is_duplicate_alert(alert):
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            self.stats['suspicious_packets'] += 1
            
            logger.warning(f"ALERT: {alert_type} - {description}")
            logger.info(f"Details: {json.dumps(details, default=str)}")
    
    def is_duplicate_alert(self, alert: Dict) -> bool:
        """Check if this alert was recently generated"""
        cutoff_time = datetime.now() - timedelta(seconds=60)
        for existing_alert in self.alerts:
            if (existing_alert['type'] == alert['type'] and
                existing_alert['timestamp'] > cutoff_time and
                existing_alert['details'].get('source_ip') == alert['details'].get('source_ip')):
                return True
        return False
    
    def get_severity(self, alert_type: str) -> str:
        """Determine alert severity"""
        severity_map = {
            'SYN_FLOOD': 'HIGH',
            'PORT_SCAN': 'MEDIUM',
            'SUSPICIOUS_PORT': 'HIGH',
            'HIGH_PACKET_RATE': 'MEDIUM'
        }
        return severity_map.get(alert_type, 'LOW')
    
    def start_capture(self, duration=None):
        """Start packet capture"""
        self.running = True
        self.capture_start_time = time.time()
        logger.info(f"Starting packet capture on {self.interface or 'default interface'}")
        logger.info(f"Capture duration: {duration} seconds")
        
        try:
            if self.pcap_file:
                # Offline analysis
                packets = rdpcap(self.pcap_file)
                for packet in packets:
                    self.packet_callback(packet)
            else:
                # Live capture with proper timeout and stop filter
                def stop_filter(packet):
                    """Stop capture after duration"""
                    if duration and (time.time() - self.capture_start_time) >= duration:
                        return True
                    return not self.running
                
                # Use store=0 to prevent memory issues
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    timeout=duration,
                    stop_filter=stop_filter,
                    store=0
                )
                
                # Ensure we wait for full duration if stopped early
                elapsed = time.time() - self.capture_start_time
                if duration and elapsed < duration:
                    remaining = duration - elapsed
                    logger.info(f"Waiting {remaining:.1f} more seconds to complete capture period...")
                    time.sleep(remaining)
                    
        except PermissionError:
            logger.error("Permission denied. Please run with administrator/root privileges.")
            logger.error("Windows: Run as Administrator")
            logger.error("Linux/Mac: Use sudo")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self.running = False 
            elapsed = time.time() - self.capture_start_time
            logger.info(f"Packet capture stopped after {elapsed:.1f} seconds")
    
    def get_dataframe(self) -> pd.DataFrame:
        """Convert captured packets to pandas DataFrame"""
        if not self.packets:
            return pd.DataFrame()
            
        df = pd.DataFrame(self.packets)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    
    def generate_statistics(self) -> Dict:
        """Generate traffic statistics"""
        df = self.get_dataframe()
        if df.empty:
            return self.stats
            
        stats = self.stats.copy()
        stats.update({
            'unique_ips': len(set(df['src_ip'].dropna()) | set(df['dst_ip'].dropna())),
            'top_talkers': df['src_ip'].value_counts().head(10).to_dict(),
            'top_destinations': df['dst_ip'].value_counts().head(10).to_dict(),
            'protocol_distribution': df['protocol'].value_counts().to_dict(),
            'average_packet_size': df['size'].mean(),
            'total_bytes': df['size'].sum()
        })
        
        if 'dst_port' in df.columns:
            stats['top_ports'] = df['dst_port'].value_counts().head(10).to_dict()
            
        return stats
    
    def visualize_traffic(self):
        """Create traffic visualizations"""
        df = self.get_dataframe()
        if df.empty:
            logger.warning("No data to visualize")
            return
            
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Packet Rate Over Time', 'Protocol Distribution',
                          'Top IPs', 'Port Distribution'),
            specs=[[{'type': 'scatter'}, {'type': 'pie'}],
                   [{'type': 'bar'}, {'type': 'bar'}]]
        )
        
        # 1. Packet rate over time
        df_time = df.set_index('timestamp').resample('10S').size()
        fig.add_trace(
            go.Scatter(x=df_time.index, y=df_time.values, mode='lines',
                      name='Packets/10s'),
            row=1, col=1
        )
        
        # 2. Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig.add_trace(
            go.Pie(labels=protocol_counts.index, values=protocol_counts.values,
                  name='Protocols'),
            row=1, col=2
        )
        
        # 3. Top source IPs
        top_sources = df['src_ip'].value_counts().head(10)
        fig.add_trace(
            go.Bar(x=top_sources.values, y=top_sources.index, orientation='h',
                  name='Source IPs'),
            row=2, col=1
        )
        
        # 4. Port distribution
        if 'dst_port' in df.columns:
            top_ports = df['dst_port'].value_counts().head(10)
            fig.add_trace(
                go.Bar(x=top_ports.index, y=top_ports.values,
                      name='Destination Ports'),
                row=2, col=2
            )
        
        fig.update_layout(height=800, showlegend=False,
                         title_text="Network Traffic Analysis Dashboard")
        fig.write_html("network_analysis.html")
        logger.info("Visualization saved to network_analysis.html")
        
        return fig
    
    def create_heatmap(self):
        """Create source-destination interaction heatmap"""
        df = self.get_dataframe()
        if df.empty:
            return
            
        # Create interaction matrix
        interactions = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
        pivot = interactions.pivot(index='src_ip', columns='dst_ip', values='count').fillna(0)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=pivot.values,
            x=pivot.columns,
            y=pivot.index,
            colorscale='Viridis',
            text=pivot.values,
            texttemplate='%{text}',
            textfont={"size": 10}
        ))
        
        fig.update_layout(
            title='Network Interaction Heatmap',
            xaxis_title='Destination IP',
            yaxis_title='Source IP',
            height=600
        )
        
        fig.write_html("interaction_heatmap.html")
        logger.info("Heatmap saved to interaction_heatmap.html")
        
        return fig
    
    def generate_report(self, output_format='markdown'):
        """Generate comprehensive security report"""
        stats = self.generate_statistics()
        
        report = f"""# Network Security Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- Total Packets Analyzed: {stats['total_packets']:,}
- Suspicious Activities Detected: {stats['suspicious_packets']:,}
- Alerts Generated: {stats['alerts_generated']:,}

## Traffic Statistics
- **Protocols**: TCP ({stats['tcp_packets']:,}), UDP ({stats['udp_packets']:,}), ICMP ({stats['icmp_packets']:,})
- **Unique IPs**: {stats.get('unique_ips', 0)}
- **Total Data**: {stats.get('total_bytes', 0) / (1024*1024):.2f} MB
- **Average Packet Size**: {stats.get('average_packet_size', 0):.2f} bytes

## Top Talkers
"""
        if 'top_talkers' in stats:
            for ip, count in list(stats['top_talkers'].items())[:5]:
                report += f"- {ip}: {count:,} packets\n"
        
        report += "\n## Alerts Summary\n"
        alert_summary = Counter([a['type'] for a in self.alerts])
        for alert_type, count in alert_summary.items():
            report += f"- **{alert_type}**: {count} occurrences\n"
        
        report += "\n## Recent Alerts (Last 10)\n"
        for alert in self.alerts[-10:]:
            report += f"\n### {alert['type']} - {alert['severity']}\n"
            report += f"**Time**: {alert['timestamp'].strftime('%H:%M:%S')}\n"
            report += f"**Description**: {alert['description']}\n"
            if alert['details'].get('source_ip'):
                report += f"**Source IP**: {alert['details']['source_ip']}\n"
        
        # Save report
        with open('security_report.md', 'w') as f:
            f.write(report)
        logger.info("Report saved to security_report.md")
        
        return report
    
    def ai_summarize_alerts(self, api_key=None):
        """Use AI to create human-readable alert summaries"""
        if not AI_AVAILABLE or not api_key:
            logger.warning("AI summarization not available")
            return None
            
        try:
            openai.api_key = api_key
            
            # Prepare alert data
            alert_text = "Network Security Alerts:\n"
            for alert in self.alerts[-20:]:  # Last 20 alerts
                alert_text += f"- {alert['type']}: {alert['description']}\n"
            
            prompt = f"""Analyze the following network security alerts and provide:
1. A brief executive summary
2. Key patterns or trends
3. Recommended actions
4. Risk assessment

{alert_text}"""
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a network security expert."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.3
            )
            
            summary = response.choices[0].message.content
            
            # Save AI summary
            with open('ai_summary.md', 'w') as f:
                f.write(f"# AI Security Analysis\n\n{summary}")
            
            logger.info("AI summary saved to ai_summary.md")
            return summary
            
        except Exception as e:
            logger.error(f"AI summarization failed: {e}")
            return None


class RuleEngine:
    """Custom rule engine for detection"""
    
    def __init__(self):
        self.rules = []
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default detection rules"""
        self.rules = [
            {
                'name': 'SSH_Brute_Force',
                'description': 'Detect SSH brute force attempts',
                'condition': lambda p: p.get('dst_port') == 22 and p.get('protocol') == 'TCP',
                'threshold': 10,
                'window': 60
            },
            {
                'name': 'DNS_Tunneling',
                'description': 'Detect potential DNS tunneling',
                'condition': lambda p: p.get('dst_port') == 53 and p.get('payload_size', 0) > 512,
                'threshold': 5,
                'window': 300
            },
            {
                'name': 'Large_Data_Transfer',
                'description': 'Detect large data exfiltration',
                'condition': lambda p: p.get('size', 0) > 10000,
                'threshold': 100,
                'window': 600
            }
        ]
    
    def add_custom_rule(self, name, description, condition, threshold=10, window=60):
        """Add a custom detection rule"""
        self.rules.append({
            'name': name,
            'description': description,
            'condition': condition,
            'threshold': threshold,
            'window': window
        })
    
    def evaluate_rules(self, packets):
        """Evaluate all rules against packet data"""
        alerts = []
        for rule in self.rules:
            matching_packets = [p for p in packets if rule['condition'](p)]
            if len(matching_packets) >= rule['threshold']:
                alerts.append({
                    'rule': rule['name'],
                    'description': rule['description'],
                    'matches': len(matching_packets),
                    'threshold': rule['threshold']
                })
        return alerts


def main():
    """Main function to run the NIDS"""
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Network Intrusion Detection System      ║
    ║           Version 1.0                     ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Configuration
    interface = 'Ethernet'  # Auto-detect or specify like 'Wi-Fi', 'eth0', 'wlan0', 'en0'
    duration = 60  # Capture duration in seconds
    
    # For Windows, try to find the correct interface
    if os.name == 'nt':
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            print("\nAvailable interfaces on Windows:")
            for i, iface in enumerate(interfaces):
                print(f"{i}: {iface['name']} - {iface.get('description', 'No description')}")
            # You can uncomment the line below to manually select
            # interface = interfaces[0]['name']  # Use first interface
        except:
            pass
    
    # Initialize NIDS
    nids = NetworkIDS(interface=interface)
    
    # Initialize rule engine
    rule_engine = RuleEngine()
    
    try:
        print(f"\n🚀 Starting packet capture for {duration} seconds...")
        print(f"📍 Interface: {interface or 'Auto-detect'}")
        print("⏹  Press Ctrl+C to stop early\n")
        print("-" * 50)
        
        # Start capture in a thread
        capture_thread = threading.Thread(
            target=nids.start_capture,
            args=(duration,),
            daemon=True
        )
        capture_thread.start()
        
        # Monitor in real-time with progress bar
        start_time = time.time()
        last_stats = {'total_packets': 0}
        
        while capture_thread.is_alive():
            elapsed = time.time() - start_time
            remaining = max(0, duration - elapsed)
            
            if elapsed >= duration:
                break
                
            # Get current stats
            stats = nids.generate_statistics()
            
            # Calculate packet rate
            packet_diff = stats['total_packets'] - last_stats['total_packets']
            
            # Progress bar
            progress = min(elapsed / duration, 1.0)
            bar_length = 30
            filled = int(bar_length * progress)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            # Display status
            print(f"\r⏱  [{bar}] {elapsed:.0f}/{duration}s | "
                  f"📦 Packets: {stats['total_packets']} | "
                  f"⚠️  Alerts: {stats['alerts_generated']} | "
                  f"📊 Rate: {packet_diff}/s", end='', flush=True)
            
            last_stats = stats.copy()
            time.sleep(1)
        
        # Wait for thread to complete
        capture_thread.join(timeout=duration + 5)
        
        print("\n" + "-" * 50)
        print("\n✅ Capture complete! Analyzing data...\n")
        
        # Check if we got any packets
        if nids.stats['total_packets'] == 0:
            print("⚠️  WARNING: No packets were captured!")
            print("\nPossible issues:")
            print("1. Wrong network interface specified")
            print("2. No network activity during capture")
            print("3. Permission issues (need admin/root)")
            print("4. Firewall blocking packet capture")
            print("\nTry:")
            print("- Running with sudo/admin privileges")
            print("- Specifying the correct interface")
            print("- Generating some network traffic (browse web, ping, etc.)")
        else:
            # Generate visualizations
            print("📊 Generating visualizations...")
            nids.visualize_traffic()
            nids.create_heatmap()
            
            # Generate report
            print("📝 Creating security report...")
            report = nids.generate_report()
            
            print("\n" + "="*50)
            print("📋 REPORT SUMMARY")
            print("="*50)
            print(report[:800] + "...")  # Print first 800 chars
            
            # Apply custom rules
            df = nids.get_dataframe()
            if not df.empty:
                rule_alerts = rule_engine.evaluate_rules(df.to_dict('records'))
                if rule_alerts:
                    print("\n" + "="*50)
                    print("🔍 CUSTOM RULE ALERTS")
                    print("="*50)
                    for alert in rule_alerts:
                        print(f"- {alert['rule']}: {alert['matches']} matches")
            
            print("\n" + "="*50)
            print("📁 FILES GENERATED")
            print("="*50)
            print("✓ nids.log - Detailed logs")
            print("✓ security_report.md - Full security report")
            print("✓ network_analysis.html - Interactive traffic dashboard")
            print("✓ interaction_heatmap.html - Network interaction visualization")
            
            # Summary statistics
            print("\n" + "="*50)
            print("📈 CAPTURE STATISTICS")
            print("="*50)
            print(f"Total Packets: {nids.stats['total_packets']:,}")
            print(f"TCP Packets: {nids.stats['tcp_packets']:,}")
            print(f"UDP Packets: {nids.stats['udp_packets']:,}")
            print(f"ICMP Packets: {nids.stats['icmp_packets']:,}")
            print(f"Alerts Generated: {nids.stats['alerts_generated']}")
            print(f"Suspicious Packets: {nids.stats['suspicious_packets']}")
        
    except KeyboardInterrupt:
        print("\n\n⛔ Stopping capture (user interrupted)...")
        nids.running = False
    except PermissionError:
        print("\n❌ ERROR: Permission denied!")
        print("This script requires administrator/root privileges.")
        print("\nWindows: Right-click and 'Run as Administrator'")
        print("Linux/Mac: Run with 'sudo python3 nids.py'")
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🛑 NIDS shutdown complete.")
    print("Thank you for using Network IDS!")


if __name__ == "__main__":
    # Check for required permissions on Linux/Mac
    if os.name != 'nt' and os.geteuid() != 0:
        print("❌ This script requires root/administrator privileges for packet capture.")
        print("Please run with: sudo python3 nids.py")
        print("\nWhy root is needed:")
        print("- Packet capture requires raw socket access")
        print("- Raw sockets need elevated privileges for security")
        sys.exit(1)
    
    main()