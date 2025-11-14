"""
Network Intrusion Detection System (NIDS)
Student Final Semester Project
Features: Packet capture, threat detection, GUI interface, AI-powered summaries
Enhanced: Statistics now reflect applied filters
Fixed: Scrollbar maintains position during live capture
"""
import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
from datetime import datetime
from collections import defaultdict
import json
import re
import ipaddress
from scapy.all import get_if_list
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6EchoRequest, ICMPv6EchoReply
from openai import OpenAI
from typing import Dict, List
import os

class ThreatDetector:
    """Analyzes network packets for potential security threats"""

    def __init__(self):
        self.threat_patterns = {
            'port_scan': defaultdict(set),
            'syn_flood': defaultdict(int),
            'icmp_flood': defaultdict(int),
            'arp_spoof': {},
            'suspicious_ports': [22, 23, 445, 3389, 1433, 3306],
            'malicious_patterns': [
                rb'\.\./', rb'<script', rb'SELECT.*FROM', rb'DROP TABLE',
                rb'eval\(', rb'exec\(', rb'cmd\.exe', rb'/etc/passwd'
            ]
        }
        self.time_windows = defaultdict(lambda: defaultdict(int))
        self.alerts = []
        self.last_reset_time = time.time()

        # Configurable thresholds
        self.thresholds = {
            'port_scan_limit': 5,
            'syn_flood_limit': 100,
            'icmp_flood_limit': 50,
            'reset_interval': 60  # Reset counters every 60 seconds
        }

    def analyze_packet(self, packet, settings=None):
        """Analyze a single packet for threats with settings support"""
        threats = []

        # Get settings or use defaults
        if settings is None:
            settings = {
                'detect_port_scan': True,
                'detect_flood': True,
                'detect_payload': True,
                'alert_threshold': 'MEDIUM'
            }

        # Auto-reset counters periodically
        current_time = time.time()
        if current_time - self.last_reset_time > self.thresholds['reset_interval']:
            self.reset_counters()
            self.last_reset_time = current_time

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Port scanning
            if TCP in packet and settings['detect_port_scan']:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags

                if flags == 2:  # SYN flag
                    self.threat_patterns['port_scan'][src_ip].add(dst_port)
                    if len(self.threat_patterns['port_scan'][src_ip]) > self.thresholds['port_scan_limit']:
                        threat = {
                            'type': 'Port Scan',
                            'severity': 'HIGH',
                            'source': src_ip,
                            'description': f'Potential port scan detected from {src_ip} (> {self.thresholds["port_scan_limit"]} ports)'
                        }
                        if self._should_alert(threat['severity'], settings['alert_threshold']):
                            threats.append(threat)

                if flags == 2 and settings['detect_flood']:
                    self.threat_patterns['syn_flood'][dst_ip] += 1
                    if self.threat_patterns['syn_flood'][dst_ip] > self.thresholds['syn_flood_limit']:
                        threat = {
                            'type': 'SYN Flood',
                            'severity': 'CRITICAL',
                            'source': src_ip,
                            'target': dst_ip,
                            'description': f'Potential SYN flood attack to {dst_ip} (> {self.thresholds["syn_flood_limit"]} SYN packets)'
                        }
                        if self._should_alert(threat['severity'], settings['alert_threshold']):
                            threats.append(threat)

                if dst_port in self.threat_patterns['suspicious_ports']:
                    threat = {
                        'type': 'Suspicious Port',
                        'severity': 'MEDIUM',
                        'source': src_ip,
                        'port': dst_port,
                        'description': f'Connection to suspicious port {dst_port}'
                    }
                    if self._should_alert(threat['severity'], settings['alert_threshold']):
                        threats.append(threat)

            if ICMP in packet and settings['detect_flood']:
                self.threat_patterns['icmp_flood'][src_ip] += 1
                if self.threat_patterns['icmp_flood'][src_ip] > self.thresholds['icmp_flood_limit']:
                    threat = {
                        'type': 'ICMP Flood',
                        'severity': 'HIGH',
                        'source': src_ip,
                        'description': f'Potential ICMP flood from {src_ip} (> {self.thresholds["icmp_flood_limit"]} packets)'
                    }
                    if self._should_alert(threat['severity'], settings['alert_threshold']):
                        threats.append(threat)

            if hasattr(packet, 'load') and settings['detect_payload']:
                payload = bytes(packet.load)
                for pattern in self.threat_patterns['malicious_patterns']:
                    if pattern in payload.lower():
                        threat = {
                            'type': 'Malicious Payload',
                            'severity': 'CRITICAL',
                            'source': src_ip,
                            'pattern': pattern.decode('utf-8', errors='ignore'),
                            'description': 'Malicious pattern detected in payload'
                        }
                        if self._should_alert(threat['severity'], settings['alert_threshold']):
                            threats.append(threat)

        if ARP in packet:
            if packet[ARP].op == 2:  # ARP reply
                arp_src = packet[ARP].psrc
                arp_mac = packet[ARP].hwsrc
                if arp_src in self.threat_patterns['arp_spoof']:
                    if self.threat_patterns['arp_spoof'][arp_src] != arp_mac:
                        threat = {
                            'type': 'ARP Spoofing',
                            'severity': 'CRITICAL',
                            'source': arp_src,
                            'description': f'ARP spoofing detected for {arp_src}'
                        }
                        if self._should_alert(threat['severity'], settings['alert_threshold']):
                            threats.append(threat)
                else:
                    self.threat_patterns['arp_spoof'][arp_src] = arp_mac

        return threats

    def _should_alert(self, threat_severity, threshold):
        severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        return severity_levels.get(threat_severity, 0) >= severity_levels.get(threshold, 1)

    def reset_counters(self):
        self.threat_patterns['syn_flood'].clear()
        self.threat_patterns['icmp_flood'].clear()
        self.threat_patterns['port_scan'].clear()

    def update_thresholds(self, port_scan_limit=None, syn_flood_limit=None, icmp_flood_limit=None, reset_interval=None):
        if port_scan_limit is not None:
            self.thresholds['port_scan_limit'] = port_scan_limit
        if syn_flood_limit is not None:
            self.thresholds['syn_flood_limit'] = syn_flood_limit
        if icmp_flood_limit is not None:
            self.thresholds['icmp_flood_limit'] = icmp_flood_limit
        if reset_interval is not None:
            self.thresholds['reset_interval'] = reset_interval


class AIAnalyzer:
    """Integrates with OpenAI API for intelligent threat analysis"""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        self.enabled = self.client is not None

    def generate_summary(self, threats: List[Dict]) -> str:
        """Generate AI-powered summary of detected threats"""
        if not self.enabled or not threats:
            return "AI analysis not available. Please set OpenAI API key."

        try:
            # Prepare threat data
            threat_summary = self._prepare_threat_data(threats)

            prompt = f"""
            The security documentation landscape has dramatically changed with digital attacks the expanding attack surface. 
            Traditional security documentation often fails because it's either too generic to be useful or too technical to be followed consistently by higher ups and stakeholders. 
            Your supervisor needs to be notifed about the new alerts that has been captured by the Network Intrusion Detection System (NIDS).
            Analyze the following network security threats detected by a NIDS:

            {threat_summary}

            Provide a BLUF, next include the following after the bluf:
            1. Overall threat level assessment
            2. Most critical threats identified
            3. Recommended immediate actions
            4. Potential attack patterns observed

            Keep the response concise and focus on actionable insights."""

            response = self.client.chat.completions.create(
                model="gpt-5-mini",
                messages=[
                    {"role": "system", "content": "You are a Cybersecurity analyst who also has exerptise in network management and incident response."},
                    {"role": "user", "content": prompt}
                ],
                temperature=1
            )

            return response.choices[0].message.content
        except Exception as e:
            return f"AI analysis error: {str(e)}"

    def _prepare_threat_data(self, threats: List[Dict]) -> str:
        """Prepare threat data for AI analysis"""
        threat_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        sources = set()

        for threat in threats:
            threat_counts[threat['type']] += 1
            severity_counts[threat['severity']] += 1
            if 'source' in threat:
                sources.add(threat['source'])

        summary = "Threat Statistics:\n"
        summary += f"Total threats: {len(threats)}\n"
        summary += f"Unique sources: {len(sources)}\n\n"

        summary += "Threats by type:\n"
        for threat_type, count in threat_counts.items():
            summary += f"- {threat_type}: {count}\n"

        summary += "\nSeverity distribution:\n"
        for severity, count in severity_counts.items():
            summary += f"- {severity}: {count}\n"

        return summary


class NetworkMonitorGUI:
    """Main GUI application for the NIDS"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.detector = ThreatDetector()
        self.ai_analyzer = AIAnalyzer()
        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.monitoring = False
        
        # Statistics counters - separate total and filtered
        self.total_packet_count = 0
        self.total_threat_count = 0
        self.filtered_packet_count = 0
        self.filtered_threat_count = 0
        
        # Protocol statistics
        self.protocol_stats = defaultdict(int)
        
        # Track active filters
        self.filters_active = False
        
        # Track user scroll state
        self.user_scrolling = False
        self.auto_scroll = True
        
        self.alert_log = []
        self.threat_summary = []

        # Setup GUI
        self.setup_gui()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.processing_thread.start()
    
    def setup_gui(self):
        """Setup the GUI components"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(notebook)
        notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard()
        
        # Live monitoring tab
        self.monitor_frame = ttk.Frame(notebook)
        notebook.add(self.monitor_frame, text="Live Monitor")
        self.setup_monitor()
        
        # Alerts tab
        self.alerts_frame = ttk.Frame(notebook)
        notebook.add(self.alerts_frame, text="Security Alerts")
        self.setup_alerts()
        
        # AI Analysis tab
        self.ai_frame = ttk.Frame(notebook)
        notebook.add(self.ai_frame, text="AI Analysis")
        self.setup_ai_analysis()
        
        # Settings tab
        self.settings_frame = ttk.Frame(notebook)
        notebook.add(self.settings_frame, text="Settings")
        self.setup_settings()
    
    def setup_dashboard(self):
        """Setup dashboard with statistics"""
        # Stats frame
        stats_frame = ttk.LabelFrame(self.dashboard_frame, text="Network Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        # Filter status indicator
        self.filter_status_label = ttk.Label(stats_frame, text="", font=('Arial', 10, 'italic'))
        self.filter_status_label.grid(row=0, column=0, columnspan=4, pady=5)
        
        # Create stat labels
        self.stats_labels = {}
        stats = [
            ('Status', 'Stopped'),
            ('Packets Captured', '0'),
            ('Threats Detected', '0'),
            ('Active Connections', '0'),
            ('Uptime', '00:00:00')
        ]
        
        for i, (label, value) in enumerate(stats):
            row = (i//2) + 1  # Start from row 1 due to filter status
            ttk.Label(stats_frame, text=f"{label}:", font=('Arial', 10, 'bold')).grid(
                row=row, column=(i%2)*2, sticky='w', padx=10, pady=5
            )
            self.stats_labels[label] = ttk.Label(stats_frame, text=value, font=('Arial', 10))
            self.stats_labels[label].grid(row=row, column=(i%2)*2+1, sticky='w', padx=10, pady=5)
        
        # Add total vs filtered stats display
        total_frame = ttk.LabelFrame(self.dashboard_frame, text="Statistics Breakdown", padding=10)
        total_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(total_frame, text="Total Packets:", font=('Arial', 10, 'bold')).grid(
            row=0, column=0, sticky='w', padx=10, pady=5
        )
        self.total_packets_label = ttk.Label(total_frame, text="0", font=('Arial', 10))
        self.total_packets_label.grid(row=0, column=1, sticky='w', padx=10, pady=5)
        
        ttk.Label(total_frame, text="Total Threats:", font=('Arial', 10, 'bold')).grid(
            row=0, column=2, sticky='w', padx=10, pady=5
        )
        self.total_threats_label = ttk.Label(total_frame, text="0", font=('Arial', 10))
        self.total_threats_label.grid(row=0, column=3, sticky='w', padx=10, pady=5)
        
        # Protocol breakdown frame
        protocol_frame = ttk.LabelFrame(self.dashboard_frame, text="Protocol Distribution", padding=10)
        protocol_frame.pack(fill='x', padx=10, pady=10)
        
        self.protocol_labels = {}
        protocols = ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IPv6', 'Unknown']
        for i, proto in enumerate(protocols):
            ttk.Label(protocol_frame, text=f"{proto}:", font=('Arial', 9)).grid(
                row=i//3, column=(i%3)*2, sticky='w', padx=10, pady=3
            )
            self.protocol_labels[proto] = ttk.Label(protocol_frame, text="0", font=('Arial', 9))
            self.protocol_labels[proto].grid(row=i//3, column=(i%3)*2+1, sticky='w', padx=10, pady=3)
        
        # Control buttons
        control_frame = ttk.Frame(self.dashboard_frame)
        control_frame.pack(pady=20)
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                    command=self.start_monitoring, style='Success.TButton')
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                   command=self.stop_monitoring, state='disabled', 
                                   style='Danger.TButton')
        self.stop_btn.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Reset Statistics", 
                  command=self.reset_statistics).pack(side='left', padx=5)
        
        # Threat summary
        threat_frame = ttk.LabelFrame(self.dashboard_frame, text="Recent Threat Summary", padding=10)
        threat_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.threat_summary = scrolledtext.ScrolledText(threat_frame, height=10, wrap=tk.WORD)
        self.threat_summary.pack(fill='both', expand=True)
    
    def setup_monitor(self):
        """Setup live packet monitoring view"""
        # Filter frame
        filter_frame = ttk.LabelFrame(self.monitor_frame, text="Packet Filters", padding=10)
        filter_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=5)
        self.protocol_filter = ttk.Combobox(filter_frame, values=['All', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IPv6'])
        self.protocol_filter.set('All')
        self.protocol_filter.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Source IP:").grid(row=0, column=2, padx=5, pady=5)
        self.src_filter = ttk.Entry(filter_frame)
        self.src_filter.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).grid(
            row=0, column=4, padx=10, pady=5
        )
        
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter).grid(
            row=0, column=5, padx=10, pady=5
        )
        
        # Auto-scroll toggle button
        self.auto_scroll_btn = ttk.Button(filter_frame, text="Auto-scroll: ON", 
                                         command=self.toggle_auto_scroll)
        self.auto_scroll_btn.grid(row=0, column=6, padx=10, pady=5)
        
        # Filter status
        self.filter_info_label = ttk.Label(filter_frame, text="No filters active", 
                                          font=('Arial', 9, 'italic'), foreground='gray')
        self.filter_info_label.grid(row=1, column=0, columnspan=6, pady=5)
        
        # Scroll status label
        self.scroll_status_label = ttk.Label(filter_frame, text="", 
                                            font=('Arial', 9, 'italic'), foreground='blue')
        self.scroll_status_label.grid(row=1, column=6, pady=5)
        
        # Packet display
        packet_frame = ttk.LabelFrame(self.monitor_frame, text="Live Packet Capture", padding=10)
        packet_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create frame for treeview and scrollbar
        tree_frame = ttk.Frame(packet_frame)
        tree_frame.pack(fill='both', expand=True)
        
        # Create treeview for packets
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Processes')
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=150)
        
        # Scrollbar
        self.packet_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=self.on_packet_scroll)
        
        self.packet_tree.pack(side='left', fill='both', expand=True)
        self.packet_scrollbar.pack(side='right', fill='y')
        
        # Bind mouse wheel events to detect user scrolling
        self.packet_tree.bind("<MouseWheel>", self.on_mouse_scroll)
        self.packet_tree.bind("<Button-4>", self.on_mouse_scroll)  # Linux
        self.packet_tree.bind("<Button-5>", self.on_mouse_scroll)  # Linux
    
    def on_packet_scroll(self, first, last):
        """Handle scrollbar movement"""
        self.packet_scrollbar.set(first, last)
        
        # Check if we're at the top (showing latest packets)
        if self.auto_scroll and float(first) == 0.0:
            self.user_scrolling = False
            self.scroll_status_label.config(text="")
        else:
            self.user_scrolling = True
            if self.monitoring:
                self.scroll_status_label.config(text="Paused (scrolling)")
    
    def on_mouse_scroll(self, event):
        if self.monitoring and self.auto_scroll:
            self.user_scrolling = False
            self.auto_scroll_btn.config(text="Auto-scroll: OFF")
            self.scroll_status_label.config(text="Manual scroll mode")
            
    
    def check_scroll_position(self):
        """Check if user has scrolled back to top"""
        if self.auto_scroll:
            try:
                # Get the current position
                if self.packet_tree.yview()[0] == 0.0:
                    self.user_scrolling = False
                    self.scroll_status_label.config(text="")
            except:
                pass
    
    def toggle_auto_scroll(self):
        """Toggle auto-scroll functionality"""
        self.auto_scroll = not self.auto_scroll
        if self.auto_scroll:
            self.auto_scroll_btn.config(text="Auto-scroll: ON")
            self.user_scrolling = False
            self.scroll_status_label.config(text="")
            # Scroll to top to show latest packets
            if len(self.packet_tree.get_children()) > 0:
                self.packet_tree.see(self.packet_tree.get_children()[0])
        else:
            self.auto_scroll_btn.config(text="Auto-scroll: OFF")
            self.scroll_status_label.config(text="Manual scroll mode")
    
    def setup_alerts(self):
        """Setup security alerts view"""
        # Alert controls
        control_frame = ttk.Frame(self.alerts_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="Clear Alerts", command=self.clear_alerts).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Export Alerts", command=self.export_alerts).pack(side='left', padx=5)
        
        # Alert display
        alert_frame = ttk.LabelFrame(self.alerts_frame, text="Security Alerts", padding=10)
        alert_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ('Time', 'Severity', 'Type', 'Source', 'Description')
        self.alert_tree = ttk.Treeview(alert_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=180)
        
        # Color tags for severity
        self.alert_tree.tag_configure('CRITICAL', background='#ffcccc')
        self.alert_tree.tag_configure('HIGH', background='#ffe6cc')
        self.alert_tree.tag_configure('MEDIUM', background='#ffffcc')
        self.alert_tree.tag_configure('LOW', background='#e6f3ff')
        
        scrollbar = ttk.Scrollbar(alert_frame, orient='vertical', command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=scrollbar.set)
        
        self.alert_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def setup_ai_analysis(self):
        """Setup AI analysis view"""
        # API key frame
        api_frame = ttk.LabelFrame(self.ai_frame, text="OpenAI Configuration", padding=10)
        api_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(api_frame, text="API Key:").grid(row=0, column=0, padx=5, pady=5)
        self.api_key_entry = ttk.Entry(api_frame, width=50, show='*')
        self.api_key_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(api_frame, text="Set API Key", command=self.set_api_key).grid(
            row=0, column=2, padx=5, pady=5
        )
        
        self.api_status = ttk.Label(api_frame, text="Status: Not configured")
        self.api_status.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Analysis controls
        control_frame = ttk.Frame(self.ai_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="Generate AI Summary", 
                  command=self.generate_ai_summary).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Auto-Analyze", 
                  command=self.toggle_auto_analyze).pack(side='left', padx=5)
        
        # AI output
        output_frame = ttk.LabelFrame(self.ai_frame, text="AI Analysis Output", padding=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.ai_output = scrolledtext.ScrolledText(output_frame, height=20, wrap=tk.WORD)
        self.ai_output.pack(fill='both', expand=True)
    
    def setup_settings(self):
        """Setup settings view with interface detection"""
        # Network interface settings
        iface_frame = ttk.LabelFrame(self.settings_frame, text="Network Interface", padding=10)
        iface_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(iface_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5)
        
        # Get available interfaces
        available_interfaces = self.get_available_interfaces()
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(iface_frame, textvariable=self.interface_var, 
                                            values=available_interfaces, width=30)
        
        # Set default interface (first available or 'eth0' if exists)
        if available_interfaces:
            if 'eth0' in available_interfaces:
                self.interface_combo.set('eth0')
            else:
                self.interface_combo.set(available_interfaces[0])
        else:
            self.interface_combo.set('eth0')
        
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Refresh interfaces button
        ttk.Button(iface_frame, text="Refresh Interfaces", 
                command=self.refresh_interfaces).grid(row=0, column=2, padx=5, pady=5)
        
        # Show interface details
        self.interface_info = ttk.Label(iface_frame, text="", font=('Arial', 9, 'italic'))
        self.interface_info.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Detection settings
        detect_frame = ttk.LabelFrame(self.settings_frame, text="Detection Settings", padding=10)
        detect_frame.pack(fill='x', padx=10, pady=10)
        
        self.detect_port_scan = tk.BooleanVar(value=True)
        ttk.Checkbutton(detect_frame, text="Detect Port Scans", 
                    variable=self.detect_port_scan).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        self.detect_flood = tk.BooleanVar(value=True)
        ttk.Checkbutton(detect_frame, text="Detect Flood Attacks", 
                    variable=self.detect_flood).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        
        self.detect_payload = tk.BooleanVar(value=True)
        ttk.Checkbutton(detect_frame, text="Detect Malicious Payloads", 
                    variable=self.detect_payload).grid(row=2, column=0, sticky='w', padx=5, pady=5)
        
        # Alert settings
        alert_frame = ttk.LabelFrame(self.settings_frame, text="Alert Settings", padding=10)
        alert_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(alert_frame, text="Alert Threshold:").grid(row=0, column=0, padx=5, pady=5)
        self.alert_threshold = ttk.Combobox(alert_frame, values=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        self.alert_threshold.set('MEDIUM')
        self.alert_threshold.grid(row=0, column=1, padx=5, pady=5)
        
        # Save settings button
        ttk.Button(self.settings_frame, text="Save Settings", 
                command=self.save_settings).pack(pady=20)
        
        # Update interface info on startup
        self.update_interface_info()

    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        
        try:
            # Method 1: Use Scapy's get_if_list
            interfaces = get_if_list()
            
            # Filter out loopback and unusable interfaces
            interfaces = [iface for iface in interfaces 
                        if iface != 'lo' and not iface.startswith('docker') 
                        and not iface.startswith('veth')]
        except:
            pass
        
        # Method 2: If psutil is available, use it for more details
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                if iface not in interfaces and iface != 'lo':
                    interfaces.append(iface)
        except:
            pass
        
        # Common interface names as fallback
        if not interfaces:
            # Common Linux interfaces
            interfaces = ['eth0', 'wlan0', 'wlp2s0', 'enp0s3', 'ens33']
            # Common Windows interfaces
            interfaces.extend(['Wi-Fi', 'Ethernet'])
            # Common macOS interfaces  
            interfaces.extend(['en0', 'en1'])
        
        return sorted(list(set(interfaces)))
    
    def refresh_interfaces(self):
        """Refresh the list of available interfaces"""
        interfaces = self.get_available_interfaces()
        self.interface_combo['values'] = interfaces
        
        # Show current interface info
        self.update_interface_info()
        
        messagebox.showinfo("Interfaces", f"Found {len(interfaces)} interfaces:\n{', '.join(interfaces[:10])}")


    def update_interface_info(self):
        """Update interface information display"""
        current_iface = self.interface_var.get()
        
        try:
            import psutil
            if current_iface in psutil.net_if_addrs():
                addrs = psutil.net_if_addrs()[current_iface]
                for addr in addrs:
                    if addr.family == 2:  # AF_INET (IPv4)
                        self.interface_info.config(
                            text=f"Selected: {current_iface} - IP: {addr.address}",
                            foreground='green'
                        )
                        return
            
            self.interface_info.config(
                text=f"Selected: {current_iface}",
                foreground='blue'
            )
        except:
            self.interface_info.config(
                text=f"Selected: {current_iface}",
                foreground='blue'
            )


    def packet_matches_filter(self, packet):
        """Check if packet matches current filters in a more intuitive way."""

        proto_filter = self.protocol_filter.get()
        src_filter = self.src_filter.get().strip()

        # If no filters are set, all packets match
        if proto_filter == 'All' and not src_filter:
            return True

        # Classify packet by network- and transport-layer protocol
        network_proto = None   # 'IPv4', 'IPv6', 'ARP', etc.
        transport_proto = None # 'TCP', 'UDP', 'ICMP', 'ICMPv6', etc.
        src = None

        # IPv4
        if IP in packet:
            network_proto = "IPv4"
            src = packet[IP].src

            if TCP in packet:
                transport_proto = "TCP"
            elif UDP in packet:
                transport_proto = "UDP"
            elif ICMP in packet:
                transport_proto = "ICMP"

        # ARP
        elif ARP in packet:
            network_proto = "ARP"
            src = packet[ARP].psrc if packet[ARP].psrc else packet[ARP].hwsrc

        # IPv6
        elif IPv6 in packet:
            network_proto = "IPv6"
            src = packet[IPv6].src

            # Next header / inner protocol
            if TCP in packet:
                transport_proto = "TCP"
            elif UDP in packet:
                transport_proto = "UDP"
            else:
                # ICMPv6 and friends
                try:
                    if packet[IPv6].nh == 58:
                        transport_proto = "ICMPv6"
                    else:
                        # Unknown or extension header
                        transport_proto = None
                except Exception:
                    transport_proto = None

        # --- Protocol filter logic ---

        if proto_filter != 'All':
            match = False

            if proto_filter == "TCP":
                match = (transport_proto == "TCP")
            elif proto_filter == "UDP":
                # Match UDP on IPv4 or IPv6
                match = (transport_proto == "UDP")
            elif proto_filter == "ICMP":
                match = (transport_proto == "ICMP")
            elif proto_filter == "ICMPv6":
                match = (transport_proto == "ICMPv6")
            elif proto_filter == "ARP":
                match = (network_proto == "ARP")
            elif proto_filter == "IPv6":
                # Any IPv6 packet, regardless of inner protocol
                match = (network_proto == "IPv6")

            if not match:
                return False

        # --- Source filter logic (IPv4 or IPv6) ---

        if src_filter:
            # Exact match on source address (IPv4 or IPv6)
            if src != src_filter:
                return False

        return True

    
    def start_monitoring(self):
        """Start packet capture"""
        self.monitoring = True
        self.start_time = time.time()
        self.stats_labels['Status'].config(text='Running', foreground='green')
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        # Reset statistics when starting
        self.reset_statistics()
        
        # Start packet capture in separate thread
        capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        capture_thread.start()
        
        # Start statistics update
        self.update_statistics()
        
        messagebox.showinfo("NIDS", "Network monitoring started")
    
    def stop_monitoring(self):
        self.monitoring = False
        self.stats_labels['Status'].config(text='Stopped', foreground='red')
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

        with self.packet_queue.mutex:
            self.packet_queue.queue.clear()
        
        messagebox.showinfo("NIDS", "Network monitoring stopped")
    
    def capture_packets(self):
        """Capture network packets on the selected interface"""
        try:
            # Get the selected interface
            selected_interface = self.interface_var.get()
            
            if not selected_interface:
                messagebox.showerror("Error", "No interface selected. Please select an interface in Settings.")
                self.stop_monitoring()
                return
            
            print(f"Starting capture on interface: {selected_interface}")
            
            def packet_handler(packet):
                if self.monitoring:
                    self.packet_queue.put(packet)
            
            # Start sniffing on the SELECTED INTERFACE
            try:
                sniff(prn=packet_handler, store=0, count=0, iface=selected_interface)
            except PermissionError:
                error_msg = f"Permission denied on interface '{selected_interface}'.\n\n"
                if os.name == 'posix':
                    error_msg += "On Linux/macOS, try running with sudo:\nsudo python nids.py"
                else:
                    error_msg += "On Windows, run as Administrator."
                messagebox.showerror("Permission Error", error_msg)
                self.stop_monitoring()
            except Exception as e:
                if "No such device" in str(e) or "not found" in str(e).lower():
                    available = self.get_available_interfaces()
                    error_msg = f"Interface '{selected_interface}' not found.\n\n"
                    error_msg += f"Available interfaces: {', '.join(available[:10])}\n\n"
                    error_msg += "Please select a valid interface in Settings."
                    messagebox.showerror("Interface Error", error_msg)
                else:
                    messagebox.showerror("Capture Error", f"Failed to capture on '{selected_interface}':\n{str(e)}")
                self.stop_monitoring()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            self.stop_monitoring()
    
    def process_packets(self):
        """Process captured packets with settings support"""
        while True:
            try:
                if not self.packet_queue.empty():
                    packet = self.packet_queue.get(timeout=0.1)
                    
                    # Always increment total count
                    self.total_packet_count += 1
                    
                    # Track protocol statistics
                    if IP in packet:
                        if TCP in packet:
                            self.protocol_stats['TCP'] += 1
                        elif UDP in packet:
                            self.protocol_stats['UDP'] += 1
                        elif ICMP in packet:
                            self.protocol_stats['ICMP'] += 1
                        else:
                            self.protocol_stats['Other IP'] += 1
                    elif ARP in packet:
                        self.protocol_stats['ARP'] += 1
                    else:
                        # Check for IPv6
                        try:
                            if IPv6 in packet:
                                self.protocol_stats['IPv6'] += 1
                                if TCP in packet:
                                    self.protocol_stats['TCP'] += 1
                                elif UDP in packet:
                                    self.protocol_stats['UDP'] += 1
                                elif packet[IPv6].nh == 58:  # ICMPv6
                                    self.protocol_stats['ICMPv6'] += 1
                            else:
                                self.protocol_stats['Unknown'] += 1
                        except:
                            self.protocol_stats['Unknown'] += 1
                    
                    # Prepare settings for analyzer - MOVED UP BEFORE USE
                    detection_settings = {
                        'detect_port_scan': self.detect_port_scan.get(),
                        'detect_flood': self.detect_flood.get(),
                        'detect_payload': self.detect_payload.get(),
                        'alert_threshold': self.alert_threshold.get()
                    }
                    
                    # Check if packet matches filter
                    matches_filter = self.packet_matches_filter(packet)
                    
                    if matches_filter:
                        # Increment filtered count
                        self.filtered_packet_count += 1
                        
                        # Display packet
                        self.display_packet(packet)
                    
                    # ALWAYS analyze for threats regardless of filter
                    threats = self.detector.analyze_packet(packet, detection_settings)
                    
                    # Process each threat
                    for threat in threats:
                        self.total_threat_count += 1
                        
                        # ALWAYS display alerts in the alerts tab and summary
                        # regardless of filter (important for security monitoring)
                        self.display_alert(threat)
                        
                        # Check if threat matches filter for filtered count
                        threat_matches = self.check_threat_filter(threat)
                        if threat_matches:
                            self.filtered_threat_count += 1
                
                time.sleep(0.01)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")

    
    def check_threat_filter(self, threat):
        """Check if threat matches current filters"""
        src_filter = self.src_filter.get().strip()
        
        if not src_filter:
            return True
        
        threat_source = threat.get('source', '')
        return threat_source == src_filter
    
    def display_packet(self, packet):
        """Display packet in the monitor view with improved scrolling"""
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            src = dst = protocol = info = "Unknown"
            length = str(len(packet)) if packet else "0"
            
            # Try to extract packet information based on layer
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    flag_str = ""
                    if flags & 0x02: flag_str += "S"  # SYN
                    if flags & 0x10: flag_str += "A"  # ACK
                    if flags & 0x01: flag_str += "F"  # FIN
                    if flags & 0x04: flag_str += "R"  # RST
                    if flags & 0x08: flag_str += "P"  # PSH
                    info = f"Port {sport} → {dport}"
                    if flag_str:
                        info += f" [{flag_str}]"
                elif UDP in packet:
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"Port {sport} → {dport}"
                    # Add common UDP service names
                    if dport == 53 or sport == 53:
                        info += " (DNS)"
                    elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
                        info += " (DHCP)"
                    elif dport == 123 or sport == 123:
                        info += " (NTP)"
                elif ICMP in packet:
                    protocol = "ICMP"
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    type_names = {
                        0: "Echo Reply",
                        3: "Dest Unreachable",
                        8: "Echo Request",
                        11: "Time Exceeded"
                    }
                    info = f"Type {icmp_type} ({type_names.get(icmp_type, 'Unknown')})"
                else:
                    # Other IP protocols
                    protocol = f"IP/{packet[IP].proto}"
                    info = f"Protocol {packet[IP].proto}"
            
            elif ARP in packet:
                protocol = "ARP"
                src = packet[ARP].psrc if packet[ARP].psrc else packet[ARP].hwsrc
                dst = packet[ARP].pdst if packet[ARP].pdst else packet[ARP].hwdst
                op = packet[ARP].op
                if op == 1:
                    info = f"Who has {packet[ARP].pdst}?"
                elif op == 2:
                    info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
                else:
                    info = f"Operation {op}"
            
            elif hasattr(packet, 'haslayer'):
                # Try to identify by Ethernet type
                if packet.haslayer('Ethernet'):
                    eth = packet['Ethernet']
                    src = eth.src
                    dst = eth.dst
                    ether_type = eth.type
                    
                    # Common Ethernet types
                    ether_types = {
                        0x0800: "IPv4",
                        0x0806: "ARP",
                        0x86DD: "IPv6",
                        0x8100: "VLAN",
                        0x88CC: "LLDP",
                        0x888E: "802.1X"
                    }
                    
                    protocol = ether_types.get(ether_type, f"Ether/0x{ether_type:04x}")
                    info = f"EtherType: 0x{ether_type:04x}"
                    
                    # Special handling for IPv6
                    if ether_type == 0x86DD:
                        try:
                            from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6EchoRequest, ICMPv6EchoReply
                            if IPv6 in packet:
                                src = packet[IPv6].src
                                dst = packet[IPv6].dst
                                
                                # Decode Next Header to actual protocol
                                nh = packet[IPv6].nh
                                next_headers = {
                                    0: "Hop-by-Hop",
                                    6: "TCP",
                                    17: "UDP",
                                    58: "ICMPv6",
                                    43: "Routing",
                                    44: "Fragment",
                                    50: "ESP",
                                    51: "AH",
                                    59: "No Next",
                                    60: "Dest Options"
                                }
                                
                                proto_name = next_headers.get(nh, f"Protocol {nh}")
                                
                                # Get more specific info for common protocols
                                if nh == 6 and TCP in packet:  # TCP
                                    protocol = "IPv6/TCP"
                                    sport = packet[TCP].sport
                                    dport = packet[TCP].dport
                                    flags = packet[TCP].flags
                                    flag_str = ""
                                    if flags & 0x02: flag_str += "S"  # SYN
                                    if flags & 0x10: flag_str += "A"  # ACK
                                    if flags & 0x01: flag_str += "F"  # FIN
                                    if flags & 0x04: flag_str += "R"  # RST
                                    if flags & 0x08: flag_str += "P"  # PSH
                                    info = f"Port {sport} → {dport}"
                                    if flag_str:
                                        info += f" [{flag_str}]"
                                elif nh == 17 and UDP in packet:  # UDP
                                    protocol = "IPv6/UDP"
                                    sport = packet[UDP].sport
                                    dport = packet[UDP].dport
                                    info = f"Port {sport} → {dport}"
                                    # Add common UDP service names
                                    if dport == 53 or sport == 53:
                                        info += " (DNS)"
                                    elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
                                        info += " (DHCP)"
                                    elif dport == 123 or sport == 123:
                                        info += " (NTP)"
                                    elif dport == 547 or sport == 547 or dport == 546 or sport == 546:
                                        info += " (DHCPv6)"
                                elif nh == 58:  # ICMPv6
                                    protocol = "ICMPv6"
                                    if ICMPv6ND_NS in packet:
                                        info = "Neighbor Solicitation"
                                    elif ICMPv6ND_NA in packet:
                                        info = "Neighbor Advertisement"
                                    elif ICMPv6EchoRequest in packet:
                                        info = "Echo Request (Ping6)"
                                    elif ICMPv6EchoReply in packet:
                                        info = "Echo Reply (Pong6)"
                                    else:
                                        info = f"Type {packet[IPv6].payload.type if hasattr(packet[IPv6].payload, 'type') else 'Unknown'}"
                                else:
                                    protocol = f"IPv6/{proto_name}"
                                    info = proto_name
                        except:
                            pass
            else:
                # Completely unknown packet type
                protocol = "RAW"
                src = "N/A"
                dst = "N/A"
                info = f"Raw packet, {len(packet)} bytes"
            
            process_name = "System/Kernel"
            try:
                if TCP in packet or UDP in packet:
                    sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                    dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
                    src_ip = packet[IP].src if IP in packet else None
                    dst_ip = packet[IP].dst if IP in packet else None

                    for conn in psutil.net_connections(kind='inet'):
                        try:
                            # Match local address
                            if conn.laddr and conn.laddr.port == sport and (not src_ip or conn.laddr.ip == src_ip):
                                if conn.pid:
                                    p = psutil.Process(conn.pid)
                                    process_name = f"{p.name()} (PID {conn.pid})"
                                else:
                                    process_name = "System/Kernel"
                                break

                            # Match remote address
                            if conn.raddr and conn.raddr.port == dport and (not dst_ip or conn.raddr.ip == dst_ip):
                                if conn.pid:
                                    p = psutil.Process(conn.pid)
                                    process_name = f"{p.name()} (PID {conn.pid})"
                                else:
                                    process_name = "System/Kernel"
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception:
                process_name = "Error"


            # Add packet to treeview
            new_item = self.packet_tree.insert('', 0, values=(timestamp, src, dst, protocol, length, info, process_name))
            
            # Auto-scroll to top only if not user scrolling and auto-scroll is enabled
            if self.auto_scroll:
                first, last = self.packet_tree.yview()
                if first <= 0.001:
                    self.packet_tree.see(new_item)
            
            # Limit displayed packets to prevent memory issues
            children = self.packet_tree.get_children()
            if len(children) > 500:  # Increased limit for better history
                # Delete oldest packets (at the bottom)
                for item in children[500:]:
                    self.packet_tree.delete(item)
                    
        except Exception as e:
            # If all else fails, still display something
            timestamp = datetime.now().strftime('%H:%M:%S')
            new_item = self.packet_tree.insert('', 0, values=(
                timestamp, 
                "Error", 
                "Error", 
                "Unknown", 
                "0", 
                f"Parse error: {str(e)[:50]}"
            ))
            
            if self.auto_scroll and not self.user_scrolling:
                self.packet_tree.see(new_item)
            
            print(f"Error displaying packet: {e}")
    
    def display_alert(self, threat):
        """Display security alert"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        values = (
            timestamp,
            threat.get('severity', 'UNKNOWN'),
            threat.get('type', 'Unknown'),
            threat.get('source', 'N/A'),
            threat.get('description', 'No description')
        )
        
        self.alert_tree.insert('', 0, values=values, tags=(threat.get('severity', 'LOW'),))
        
        # Update threat summary
        summary = f"[{timestamp}] {threat.get('severity', 'UNKNOWN')}: {threat.get('description', 'No description')}\n"
        self.threat_summary.insert('1.0', summary)
        
        # Store for AI analysis
        self.detector.alerts.append(threat)
    
    def update_statistics(self):
        """Update dashboard statistics"""
        if self.monitoring:
            # Update counters based on filter status
            if self.filters_active:
                self.stats_labels['Packets Captured'].config(text=f"{self.filtered_packet_count} (filtered)")
                self.stats_labels['Threats Detected'].config(text=f"{self.filtered_threat_count} (filtered)")
            else:
                self.stats_labels['Packets Captured'].config(text=str(self.total_packet_count))
                self.stats_labels['Threats Detected'].config(text=str(self.total_threat_count))
            
            # Update total statistics
            self.total_packets_label.config(text=str(self.total_packet_count))
            self.total_threats_label.config(text=str(self.total_threat_count))
            
            # Update protocol distribution
            for proto in ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IPv6', 'Unknown']:
                count = self.protocol_stats.get(proto, 0)
                if proto == 'Unknown':
                    # Include 'Other IP' and actual 'Unknown' in the Unknown category
                    count += self.protocol_stats.get('Other IP', 0)
                self.protocol_labels[proto].config(text=str(count))
            
            # Update uptime
            uptime = int(time.time() - self.start_time)
            hours = uptime // 3600
            minutes = (uptime % 3600) // 60
            seconds = uptime % 60
            self.stats_labels['Uptime'].config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Schedule next update
            self.root.after(1000, self.update_statistics)
    
    def apply_filter(self):
        """Apply packet filters and update statistics"""
        proto_filter = self.protocol_filter.get()
        src_filter = self.src_filter.get().strip()
        
        if proto_filter != 'All' or src_filter:
            self.filters_active = True
            filter_text = f"Active Filters: Protocol={proto_filter}"
            if src_filter:
                filter_text += f", Source IP={src_filter}"
            
            self.filter_info_label.config(text=filter_text, foreground='blue')
            self.filter_status_label.config(text="📊 Statistics showing filtered data", foreground='blue')
            
            # Reset filtered counters to recount from existing data
            self.filtered_packet_count = 0
            self.filtered_threat_count = 0
            
            # Clear the packet display
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            
            messagebox.showinfo("Filter", f"Filter applied: {filter_text}")
        else:
            messagebox.showinfo("Filter", "No filter criteria specified")
    
    def clear_filter(self):
        """Clear all filters and show all statistics"""
        self.protocol_filter.set('All')
        self.src_filter.delete(0, tk.END)
        self.filters_active = False
        
        self.filter_info_label.config(text="No filters active", foreground='gray')
        self.filter_status_label.config(text="", foreground='black')
        
        # Reset filtered counts to match total
        self.filtered_packet_count = self.total_packet_count
        self.filtered_threat_count = self.total_threat_count
        
        messagebox.showinfo("Filter", "All filters cleared")
    
    def reset_statistics(self):
        """Reset all statistics counters"""
        self.total_packet_count = 0
        self.total_threat_count = 0
        self.filtered_packet_count = 0
        self.filtered_threat_count = 0
        self.protocol_stats.clear()
        
        # Update display
        self.stats_labels['Packets Captured'].config(text='0')
        self.stats_labels['Threats Detected'].config(text='0')
        self.total_packets_label.config(text='0')
        self.total_threats_label.config(text='0')
        
        # Reset protocol labels
        for proto_label in self.protocol_labels.values():
            proto_label.config(text='0')
        
        # Clear packet and alert displays
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Reset scroll state
        self.user_scrolling = False
        self.scroll_status_label.config(text="")
        
        messagebox.showinfo("Statistics", "All statistics have been reset")
    
    def clear_alerts(self):
        """Clear all alerts"""
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        self.threat_summary.delete('1.0', tk.END)
        self.detector.alerts.clear()
        self.filtered_threat_count = 0
        self.total_threat_count = 0
        messagebox.showinfo("Alerts", "All alerts cleared")
    
    def export_alerts(self):
        """Export alerts to JSON file"""
        if not self.detector.alerts:
            messagebox.showwarning("Export", "No alerts to export")
            return
        
        filename = f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.detector.alerts, f, indent=2, default=str)
        
        messagebox.showinfo("Export", f"Alerts exported to {filename}")
    
    def set_api_key(self):
        """Set OpenAI API key"""
        api_key = self.api_key_entry.get()
        if api_key:
            try:
                self.ai_analyzer = AIAnalyzer(api_key)
                if self.ai_analyzer.enabled:
                    self.api_status.config(text="Status: Configured", foreground='green')
                    messagebox.showinfo("API Key", "OpenAI API key set successfully")
                else:
                    self.api_status.config(text="Status: Invalid key", foreground='red')
                    messagebox.showerror("API Key", "Failed to set API key")
            except Exception as e:
                self.api_status.config(text=f"Status: Error - {str(e)}", foreground='red')
                messagebox.showerror("API Key", f"Error setting API key: {str(e)}")
        else:
            messagebox.showwarning("API Key", "Please enter an API key")
    
    def generate_ai_summary(self):
        """Generate AI summary of threats"""
        if not self.detector.alerts:
            messagebox.showwarning("AI Analysis", "No threats to analyze")
            return
        
        if not self.ai_analyzer.enabled:
            messagebox.showwarning("AI Analysis", "Please configure OpenAI API key first")
            return
        
        # Show loading message
        self.ai_output.delete('1.0', tk.END)
        self.ai_output.insert('1.0', "Generating AI analysis...")
        
        # Generate summary in thread
        def generate():
            summary = self.ai_analyzer.generate_summary(self.detector.alerts)
            self.ai_output.delete('1.0', tk.END)
            self.ai_output.insert('1.0', f"AI Security Analysis\n{'='*50}\n\n{summary}")
        
        threading.Thread(target=generate, daemon=True).start()
    
    def toggle_auto_analyze(self):
        """Toggle automatic AI analysis"""
        messagebox.showinfo("Auto-Analyze", "Auto-analyze feature toggled")
    
    def save_settings(self):
        """Save application settings with threshold updates"""
        settings = {
            'interface': self.interface_var.get(),  # Save the selected interface
            'detect_port_scan': self.detect_port_scan.get(),
            'detect_flood': self.detect_flood.get(),
            'detect_payload': self.detect_payload.get(),
            'alert_threshold': self.alert_threshold.get()
        }
        
        # Update detector thresholds when saving
        self.update_detection_thresholds()
        
        # Update interface info display
        self.update_interface_info()
        
        with open('nids_settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
        
        messagebox.showinfo("Settings", f"Settings saved.\nInterface set to: {self.interface_var.get()}")
    
    def update_detection_thresholds(self):
        """Update detection thresholds based on GUI settings"""
        # This method can be called when settings are saved
        try:
            # Get values from GUI (you'd need to add these Entry fields to settings)
            # For now, using default values
            self.detector.update_thresholds(
                port_scan_limit=15,  # Could be from a GUI field
                syn_flood_limit=100,  # Could be from a GUI field
                icmp_flood_limit=50,  # Could be from a GUI field
                reset_interval=60     # Could be from a GUI field
            )
        except Exception as e:
            print(f"Error updating thresholds: {e}")
        
    def run(self):
        """Run the GUI application"""
        # Configure styles
        style = ttk.Style()
        style.configure('Success.TButton', foreground='green')
        style.configure('Danger.TButton', foreground='red')
        
        # Start the GUI
        self.root.mainloop()

def main():
    """Main entry point"""
    print("""
    ╔════════════════════════════════════════════════════╗
    ║     Network Intrusion Detection System (NIDS)      ║
    ║     With Fixed Scrollbar & Auto-scroll Control     ║
    ╚════════════════════════════════════════════════════╝
    """)
    
    # Check for root/admin privileges (recommended for packet capture)
    import os
    if os.name == 'posix' and os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges may limit packet capture capabilities")
        print("   Consider running with: sudo python nids.py\n")
    
    # Create and run the application
    app = NetworkMonitorGUI()
    app.run()

if __name__ == "__main__":
    main()