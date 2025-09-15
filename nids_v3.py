#!/usr/bin/env python3
"""
Enhanced Network Intrusion Detection System (NIDS) with Detailed Connection Monitoring
Features: Source/Destination IP and Port Tracking, Real-time Monitoring, AI Analysis
No WinPcap/Npcap required - Works on all platforms!

Author: Network Security Tool v3.1
"""

import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import queue
import webbrowser
import re

# Core monitoring (no special drivers needed)
import psutil
import socket
import subprocess
import platform

# OpenAI Integration
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    print("🤖 OpenAI library not found. Install with: pip install openai")

# Data processing
try:
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import seaborn as sns
    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False
    print("📊 Plotting libraries not found. Install with: pip install pandas matplotlib seaborn")

class FriendlyNIDS:
    """Enhanced Network IDS with IP/Port Monitoring - Easy Start-Up"""
    
    def __init__(self):
        """Initialize the enhanced NIDS"""
        self.running = False
        self.monitoring_thread = None
        self.alerts = []
        self.connections = {}
        self.connection_history = []  # Store detailed connection history
        self.network_stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'total_bytes_sent': 0,
            'total_bytes_recv': 0,
            'alerts_count': 0,
            'unique_source_ips': set(),
            'unique_dest_ips': set(),
            'port_activity': defaultdict(int)
        }
        
        # Detection settings (user-friendly)
        self.settings = {
            'max_connections_per_ip': 50,
            'suspicious_ports': [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6666, 6667, 31337],
            'monitor_interval': 2,  # Check frequency
            'monitor_interval_unit': 'seconds',
            'capture_duration': 5,  # Total capture duration
            'capture_duration_unit': 'minutes',
            'max_data_transfer_mb': 100,
            'alert_retention_value': 24,
            'alert_retention_unit': 'hours',
            'openai_api_key': '',  # OpenAI API key
            'openai_model': 'gpt-5-nano',  # Default model changed to gpt-5-nano
            'auto_analyze': False  # Auto-analyze with AI when scan completes
        }
        
        # Load API key from environment if available
        if os.environ.get('OPENAI_API_KEY'):
            self.settings['openai_api_key'] = os.environ.get('OPENAI_API_KEY')
        
        # Monitoring control variables
        self.monitor_start_time = None
        self.monitor_end_time = None
        
        # Known suspicious ports with friendly names
        self.port_names = {
            23: 'Telnet (Insecure)',
            135: 'Windows RPC',
            139: 'NetBIOS',
            445: 'Windows SMB',
            1433: 'SQL Server',
            3389: 'Remote Desktop',
            4444: 'Potential Backdoor',
            5900: 'VNC Remote Access',
            6666: 'IRC Bot',
            6667: 'IRC Chat',
            31337: 'Back Orifice Trojan'
        }
        
        # Common port descriptions
        self.common_ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            587: 'SMTP (Submission)',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate'
        }
        
        self.setup_gui()
    
    def get_port_description(self, port):
        """Get description for a port number"""
        if port in self.port_names:
            return self.port_names[port]
        elif port in self.common_ports:
            return self.common_ports[port]
        else:
            return f"Port {port}"
    
    def get_monitor_interval_seconds(self):
        """Convert monitor interval to seconds based on selected unit"""
        value = self.settings['monitor_interval']
        unit = self.settings['monitor_interval_unit']
        
        if unit == 'minutes':
            return value * 60
        elif unit == 'hours':
            return value * 3600
        else:  # seconds
            return value
    
    def get_capture_duration_seconds(self):
        """Convert capture duration to seconds based on selected unit"""
        value = self.settings['capture_duration']
        unit = self.settings['capture_duration_unit']
        
        if unit == 'minutes':
            return value * 60
        elif unit == 'hours':
            return value * 3600
        elif unit == 'days':
            return value * 86400
        else:  # seconds
            return value
    
    def get_alert_retention_hours(self):
        """Convert alert retention to hours based on selected unit"""
        value = self.settings['alert_retention_value']
        unit = self.settings['alert_retention_unit']
        
        if unit == 'minutes':
            return value / 60
        elif unit == 'hours':
            return value
        elif unit == 'days':
            return value * 24
        else:  # seconds
            return value / 3600
    
    def setup_gui(self):
        """Create the enhanced GUI"""
        self.root = tk.Tk()
        self.root.title("🛡️ Network Connection Monitor - IP & Port Tracker")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2c3e50', foreground='white')
        style.configure('Status.TLabel', font=('Arial', 12), background='#2c3e50', foreground='#ecf0f1')
        style.configure('Good.TLabel', font=('Arial', 10, 'bold'), background='#2c3e50', foreground='#27ae60')
        style.configure('Warning.TLabel', font=('Arial', 10, 'bold'), background='#2c3e50', foreground='#f39c12')
        style.configure('Alert.TLabel', font=('Arial', 10, 'bold'), background='#2c3e50', foreground='#e74c3c')
        
        self.create_header()
        self.create_control_panel()
        self.create_status_dashboard()
        self.create_connection_monitor_panel()
        self.create_alerts_panel()
        
        # Status update queue for thread safety
        self.status_queue = queue.Queue()
        self.root.after(100, self.process_status_updates)
    
    def create_header(self):
        """Create the header section"""
        header_frame = tk.Frame(self.root, bg='#34495e', height=80)
        header_frame.pack(fill='x', padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        title_label = ttk.Label(header_frame, text="🛡️ Network IDS", style='Title.TLabel')
        title_label.pack(pady=15)
        
        subtitle_label = ttk.Label(header_frame, text="Real-time IP & Port Monitoring • Connection Analysis • Security Detection", style='Status.TLabel')
        subtitle_label.pack()
    
    def create_control_panel(self):
        """Create control buttons"""
        control_frame = tk.Frame(self.root, bg='#2c3e50')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Start/Stop button
        self.start_button = tk.Button(
            control_frame, 
            text="🚀 Start Monitoring", 
            command=self.toggle_monitoring,
            bg='#27ae60', 
            fg='white', 
            font=('Arial', 12, 'bold'),
            padx=20, 
            pady=5
        )
        self.start_button.pack(side='left', padx=5)
        
        # Settings button
        settings_button = tk.Button(
            control_frame, 
            text="⚙️ Settings", 
            command=self.show_settings,
            bg='#3498db', 
            fg='white', 
            font=('Arial', 10),
            padx=15, 
            pady=5
        )
        settings_button.pack(side='left', padx=5)
        
        # AI Analysis button
        self.ai_button = tk.Button(
            control_frame, 
            text="🤖 AI Analysis", 
            command=self.perform_ai_analysis,
            bg='#9b59b6', 
            fg='white', 
            font=('Arial', 10),
            padx=15, 
            pady=5,
            state='disabled' if not HAS_OPENAI else 'normal'
        )
        self.ai_button.pack(side='left', padx=5)
        
        # Export button
        export_button = tk.Button(
            control_frame, 
            text="📊 Export Report", 
            command=self.export_report,
            bg='#95a5a6', 
            fg='white', 
            font=('Arial', 10),
            padx=15, 
            pady=5
        )
        export_button.pack(side='left', padx=5)
        
        # Clear alerts button
        clear_button = tk.Button(
            control_frame, 
            text="🗑️ Clear", 
            command=self.clear_alerts,
            bg='#e67e22', 
            fg='white', 
            font=('Arial', 10),
            padx=15, 
            pady=5
        )
        clear_button.pack(side='left', padx=5)
        
        # Status indicator
        self.status_label = ttk.Label(control_frame, text="⚫ Stopped", style='Status.TLabel')
        self.status_label.pack(side='right', padx=10)
        
        # Time remaining label
        self.time_remaining_label = ttk.Label(control_frame, text="", style='Status.TLabel')
        self.time_remaining_label.pack(side='right', padx=10)
    
    def create_status_dashboard(self):
        """Create the status dashboard"""
        dashboard_frame = tk.LabelFrame(self.root, text="📊 Connection Statistics", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
        dashboard_frame.pack(fill='x', padx=10, pady=5)
        
        # Create stats grid
        stats_frame = tk.Frame(dashboard_frame, bg='#2c3e50')
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        # Stats labels
        self.stats_labels = {}
        stats_info = [
            ('connections', '🔗 Active Connections', '0'),
            ('unique_sources', '📤 Unique Source IPs', '0'),
            ('unique_dests', '📥 Unique Dest IPs', '0'),
            ('port_count', '🔌 Active Ports', '0'),
            ('suspicious', '⚠️ Suspicious Activity', '0'),
            ('data_sent', '📤 Data Sent', '0 MB'),
            ('data_recv', '📥 Data Received', '0 MB'),
            ('alerts', '🚨 Total Alerts', '0'),
            ('uptime', '⏱️ Monitoring Time', '00:00:00')
        ]
        
        for i, (key, label, initial) in enumerate(stats_info):
            row = i // 3
            col = i % 3
            
            stat_frame = tk.Frame(stats_frame, bg='#34495e', relief='raised', bd=1)
            stat_frame.grid(row=row, column=col, padx=5, pady=5, sticky='ew')
            
            tk.Label(stat_frame, text=label, bg='#34495e', fg='#bdc3c7', font=('Arial', 9)).pack(pady=(5,0))
            self.stats_labels[key] = tk.Label(stat_frame, text=initial, bg='#34495e', fg='white', font=('Arial', 14, 'bold'))
            self.stats_labels[key].pack(pady=(0,5))
        
        # Configure grid weights
        for i in range(3):
            stats_frame.columnconfigure(i, weight=1)
    
    def create_connection_monitor_panel(self):
        """Create the connection monitoring panel"""
        conn_frame = tk.LabelFrame(self.root, text="🔍 Live Connection Monitor (Source → Destination)", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
        conn_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create Treeview for connection details
        columns = ('Time', 'Source IP', 'Source Port', 'Destination IP', 'Dest Port', 'Protocol', 'Status', 'Process', 'Port Info')
        self.conn_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        column_widths = {
            'Time': 80,
            'Source IP': 120,
            'Source Port': 80,
            'Destination IP': 120,
            'Dest Port': 80,
            'Protocol': 70,
            'Status': 100,
            'Process': 100,
            'Port Info': 150
        }
        
        for col in columns:
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(conn_frame, orient='vertical', command=self.conn_tree.yview)
        h_scrollbar = ttk.Scrollbar(conn_frame, orient='horizontal', command=self.conn_tree.xview)
        self.conn_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack elements
        self.conn_tree.grid(row=0, column=0, sticky='nsew', padx=(10, 0), pady=(10, 0))
        v_scrollbar.grid(row=0, column=1, sticky='ns', pady=(10, 0))
        h_scrollbar.grid(row=1, column=0, sticky='ew', padx=(10, 0))
        
        # Configure grid weights
        conn_frame.grid_rowconfigure(0, weight=1)
        conn_frame.grid_columnconfigure(0, weight=1)
    
    def create_alerts_panel(self):
        """Create the alerts panel"""
        alerts_frame = tk.LabelFrame(self.root, text="🚨 Security Alerts & Connection Log", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
        alerts_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Alerts text area with scrollbar
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame, 
            height=8, 
            bg='#1a1a1a', 
            fg='#ecf0f1', 
            font=('Consolas', 10),
            wrap=tk.WORD
        )
        self.alerts_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add initial message
        self.alerts_text.insert(tk.END, "🛡️ Network Connection Monitor Ready - Click 'Start Monitoring' to begin\n")
        self.alerts_text.insert(tk.END, "📡 Will track all source and destination IPs and ports\n")
        self.alerts_text.insert(tk.END, "🤖 AI Analysis available when monitoring completes\n")
        self.alerts_text.insert(tk.END, "=" * 70 + "\n\n")
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if not self.running:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start the monitoring process"""
        self.running = True
        self.monitor_start_time = datetime.now()
        duration_seconds = self.get_capture_duration_seconds()
        self.monitor_end_time = self.monitor_start_time + timedelta(seconds=duration_seconds)
        
        self.start_button.config(text="🛑 Stop Monitoring", bg='#e74c3c')
        self.status_label.config(text="🟢 Monitoring Active")
        
        # Clear previous data
        self.alerts.clear()
        self.connections.clear()
        self.connection_history.clear()
        self.network_stats['unique_source_ips'].clear()
        self.network_stats['unique_dest_ips'].clear()
        self.network_stats['port_activity'].clear()
        
        # Clear connection tree
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start timer update thread
        self.timer_thread = threading.Thread(target=self.update_timer, daemon=True)
        self.timer_thread.start()
        
        duration_text = f"{self.settings['capture_duration']} {self.settings['capture_duration_unit']}"
        interval_text = f"{self.settings['monitor_interval']} {self.settings['monitor_interval_unit']}"
        self.add_alert("INFO", "🚀 Network monitoring started", 
                      f"Monitoring for {duration_text}, checking every {interval_text}")
    
    def stop_monitoring(self, auto_stopped=False):
        """Stop the monitoring process"""
        self.running = False
        self.start_button.config(text="🚀 Start Monitoring", bg='#27ae60')
        self.status_label.config(text="⚫ Stopped")
        self.time_remaining_label.config(text="")
        
        if auto_stopped:
            self.add_alert("INFO", "⏱️ Monitoring duration completed", 
                          f"Scan completed after {self.settings['capture_duration']} {self.settings['capture_duration_unit']}")
            
            # Show summary
            self.show_monitoring_summary()
            
            # Auto-analyze if enabled
            if self.settings['auto_analyze'] and self.settings['openai_api_key']:
                self.root.after(1000, self.perform_ai_analysis)
        else:
            self.add_alert("INFO", "🛑 Network monitoring stopped", "Monitoring session manually ended")
    
    def show_monitoring_summary(self):
        """Show a summary of monitoring results"""
        # Count only active ports (with count > 0)
        active_ports = sum(1 for count in self.network_stats['port_activity'].values() if count > 0)
        
        summary = f"""
🔍 Monitoring Summary:
• Unique Source IPs: {len(self.network_stats['unique_source_ips'])}
• Unique Destination IPs: {len(self.network_stats['unique_dest_ips'])}
• Total Connections Monitored: {len(self.connection_history)}
• Active Ports Used: {active_ports}
• Suspicious Connections: {self.network_stats['suspicious_connections']}
"""
        self.add_alert("INFO", "📊 Session Summary", summary)
    
    def update_timer(self):
        """Update the remaining time display"""
        while self.running and self.monitor_end_time:
            try:
                remaining = self.monitor_end_time - datetime.now()
                if remaining.total_seconds() > 0:
                    hours, remainder = divmod(int(remaining.total_seconds()), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    time_str = f"⏱️ {hours:02d}:{minutes:02d}:{seconds:02d}"
                    
                    self.status_queue.put({
                        'type': 'timer_update',
                        'data': time_str
                    })
                else:
                    # Time's up - stop monitoring
                    self.status_queue.put({
                        'type': 'auto_stop',
                        'data': None
                    })
                    break
                
                time.sleep(1)
            except Exception as e:
                break
    
    def monitoring_loop(self):
        """Main monitoring loop with duration control"""
        while self.running:
            try:
                # Check if monitoring duration has expired
                if self.monitor_end_time and datetime.now() >= self.monitor_end_time:
                    # Queue auto-stop in main thread
                    self.status_queue.put({
                        'type': 'auto_stop',
                        'data': None
                    })
                    break
                
                self.check_network_connections()
                self.update_statistics()
                
                # Use converted interval in seconds
                time.sleep(self.get_monitor_interval_seconds())
                
            except Exception as e:
                self.add_alert("ERROR", "🔥 Monitoring Error", f"Error in monitoring loop: {str(e)}")
                break
    
    def check_network_connections(self):
        """Check current network connections and track IPs/Ports"""
        try:
            current_connections = psutil.net_connections(kind='inet')
            current_time = datetime.now()
            
            # Group connections by remote IP
            ip_connections = defaultdict(list)
            
            for conn in current_connections:
                # Track all connections with details
                conn_info = self.extract_connection_info(conn, current_time)
                if conn_info:
                    self.connection_history.append(conn_info)
                    
                    # Update stats
                    if conn_info['source_ip']:
                        self.network_stats['unique_source_ips'].add(conn_info['source_ip'])
                    if conn_info['dest_ip']:
                        self.network_stats['unique_dest_ips'].add(conn_info['dest_ip'])
                    if conn_info['source_port']:
                        self.network_stats['port_activity'][conn_info['source_port']] += 1
                    if conn_info['dest_port']:
                        self.network_stats['port_activity'][conn_info['dest_port']] += 1
                
                if conn.raddr:  # Has remote address
                    remote_ip = conn.raddr.ip
                    ip_connections[remote_ip].append(conn)
            
            # Analyze each IP
            for remote_ip, conns in ip_connections.items():
                self.analyze_ip_connections(remote_ip, conns, current_time)
            
            # Update connection display
            self.update_connection_display(current_connections)
            
        except Exception as e:
            self.add_alert("ERROR", "Connection Check Failed", f"Could not check connections: {str(e)}")
    
    def extract_connection_info(self, conn, timestamp):
        """Extract detailed connection information"""
        try:
            # Get process name
            process_name = "Unknown"
            try:
                if conn.pid:
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
            except:
                pass
            
            # Determine protocol
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            
            # Extract source and destination info
            source_ip = conn.laddr.ip if conn.laddr else None
            source_port = conn.laddr.port if conn.laddr else None
            dest_ip = conn.raddr.ip if conn.raddr else None
            dest_port = conn.raddr.port if conn.raddr else None
            
            return {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'source_port': source_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'protocol': protocol,
                'status': conn.status,
                'process': process_name,
                'pid': conn.pid
            }
        except:
            return None
    
    def analyze_ip_connections(self, remote_ip, connections, current_time):
        """Analyze connections from a specific IP"""
        conn_count = len(connections)
        
        # Check for too many connections from single IP
        if conn_count > self.settings['max_connections_per_ip']:
            self.add_alert(
                "HIGH", 
                f"🚨 Suspicious Connection Volume", 
                f"IP {remote_ip} has {conn_count} active connections (threshold: {self.settings['max_connections_per_ip']})"
            )
        
        # Check for connections to suspicious ports
        for conn in connections:
            if conn.laddr and conn.laddr.port in self.settings['suspicious_ports']:
                port_name = self.port_names.get(conn.laddr.port, f"Port {conn.laddr.port}")
                source = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
                dest = f"{remote_ip}:{conn.raddr.port}" if conn.raddr else remote_ip
                self.add_alert(
                    "HIGH", 
                    f"🔓 Suspicious Port Access Detected", 
                    f"Connection: {source} → {dest} ({port_name})"
                )
        
        # Track connection patterns
        self.connections[remote_ip] = {
            'count': conn_count,
            'last_seen': current_time,
            'local_ports': list(set([conn.laddr.port for conn in connections if conn.laddr])),
            'remote_ports': list(set([conn.raddr.port for conn in connections if conn.raddr]))
        }
    
    def update_connection_display(self, connections):
        """Update the connection display tree with source and destination details"""
        # Clear existing items
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        
        # Add current connections (limit display for performance)
        for i, conn in enumerate(connections[-100:]):
            try:
                conn_info = self.extract_connection_info(conn, datetime.now())
                if not conn_info:
                    continue
                
                # Format source and destination
                source_ip = conn_info['source_ip'] or 'N/A'
                source_port = str(conn_info['source_port']) if conn_info['source_port'] else 'N/A'
                dest_ip = conn_info['dest_ip'] or 'N/A'
                dest_port = str(conn_info['dest_port']) if conn_info['dest_port'] else 'N/A'
                
                # Get port description
                port_info = ""
                if conn_info['dest_port']:
                    port_info = self.get_port_description(conn_info['dest_port'])
                elif conn_info['source_port']:
                    port_info = self.get_port_description(conn_info['source_port'])
                
                # Determine row color based on port suspicion
                tag = ''
                if conn_info['source_port'] in self.settings['suspicious_ports'] or \
                   conn_info['dest_port'] in self.settings['suspicious_ports']:
                    tag = 'suspicious'
                
                # Insert into tree
                item = self.conn_tree.insert('', 0, values=(
                    datetime.now().strftime('%H:%M:%S'),
                    source_ip,
                    source_port,
                    dest_ip,
                    dest_port,
                    conn_info['protocol'],
                    conn_info['status'],
                    conn_info['process'],
                    port_info
                ), tags=(tag,))
                
                # Configure tag colors
                if tag == 'suspicious':
                    self.conn_tree.tag_configure('suspicious', background='#e74c3c', foreground='white')
                
            except Exception as e:
                continue
    
    def update_statistics(self):
        """Update network statistics"""
        try:
            # Get network IO stats
            net_io = psutil.net_io_counters()
            
            # Update stats
            self.network_stats['total_connections'] = len(psutil.net_connections())
            self.network_stats['suspicious_connections'] = len([ip for ip, data in self.connections.items() 
                                                               if data['count'] > self.settings['max_connections_per_ip']])
            self.network_stats['total_bytes_sent'] = net_io.bytes_sent
            self.network_stats['total_bytes_recv'] = net_io.bytes_recv
            self.network_stats['alerts_count'] = len(self.alerts)
            
            # Calculate uptime
            if self.monitor_start_time:
                uptime = datetime.now() - self.monitor_start_time
                uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            else:
                uptime_str = "00:00:00"
            
            # Queue stats update for main thread
            self.status_queue.put({
                'type': 'stats_update',
                'data': {
                    'connections': str(self.network_stats['total_connections']),
                    'unique_sources': str(len(self.network_stats['unique_source_ips'])),
                    'unique_dests': str(len(self.network_stats['unique_dest_ips'])),
                    'port_count': str(len(self.network_stats['port_activity'])),
                    'suspicious': str(self.network_stats['suspicious_connections']),
                    'data_sent': f"{self.network_stats['total_bytes_sent'] / (1024*1024):.1f} MB",
                    'data_recv': f"{self.network_stats['total_bytes_recv'] / (1024*1024):.1f} MB",
                    'alerts': str(self.network_stats['alerts_count']),
                    'uptime': uptime_str
                }
            })
            
        except Exception as e:
            self.add_alert("ERROR", "Stats Update Failed", f"Could not update statistics: {str(e)}")
    
    def add_alert(self, severity, title, description):
        """Add a new alert"""
        alert = {
            'timestamp': datetime.now(),
            'severity': severity,
            'title': title,
            'description': description
        }
        
        self.alerts.append(alert)
        
        # Queue alert for GUI update
        self.status_queue.put({
            'type': 'new_alert',
            'data': alert
        })
    
    def process_status_updates(self):
        """Process queued status updates (runs in main thread)"""
        try:
            while True:
                try:
                    update = self.status_queue.get_nowait()
                    
                    if update['type'] == 'stats_update':
                        # Update stats labels
                        for key, value in update['data'].items():
                            if key in self.stats_labels:
                                self.stats_labels[key].config(text=value)
                    
                    elif update['type'] == 'new_alert':
                        # Add alert to display
                        alert = update['data']
                        severity_icon = {'INFO': 'ℹ️', 'LOW': '⚠️', 'MEDIUM': '🔸', 'HIGH': '🚨', 'ERROR': '❌'}
                        icon = severity_icon.get(alert['severity'], '•')
                        
                        alert_text = f"[{alert['timestamp'].strftime('%H:%M:%S')}] {icon} {alert['title']}\n"
                        alert_text += f"    {alert['description']}\n\n"
                        
                        self.alerts_text.insert(tk.END, alert_text)
                        self.alerts_text.see(tk.END)  # Auto-scroll to bottom
                    
                    elif update['type'] == 'timer_update':
                        self.time_remaining_label.config(text=update['data'])
                    
                    elif update['type'] == 'auto_stop':
                        # Auto-stop monitoring when duration expires
                        if self.running:
                            self.stop_monitoring(auto_stopped=True)
                
                except queue.Empty:
                    break
        except:
            pass
        
        # Schedule next update
        self.root.after(100, self.process_status_updates)
    
    def perform_ai_analysis(self):
        """Perform AI analysis of the scan results"""
        if not HAS_OPENAI:
            messagebox.showwarning("OpenAI Not Available", 
                                  "Please install the OpenAI library:\npip install openai")
            return
        
        if not self.settings['openai_api_key']:
            # Prompt for API key
            api_key = simpledialog.askstring("OpenAI API Key", 
                                            "Please enter your OpenAI API key:",
                                            show='*')
            if not api_key:
                return
            self.settings['openai_api_key'] = api_key
        
        try:
            # Prepare scan data for analysis
            scan_summary = self.prepare_scan_summary()
            
            # Show progress
            progress_window = tk.Toplevel(self.root)
            progress_window.title("🤖 AI Analysis in Progress")
            progress_window.geometry("400x150")
            progress_window.configure(bg='#2c3e50')
            progress_window.transient(self.root)
            progress_window.grab_set()
            
            tk.Label(progress_window, text="🤖 Analyzing scan results with AI...", 
                    bg='#2c3e50', fg='white', font=('Arial', 12)).pack(pady=30)
            progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
            progress_bar.pack(padx=40, pady=10)
            progress_bar.start()
            
            # Perform analysis in thread
            def analyze():
                try:
                    client = openai.OpenAI(api_key=self.settings['openai_api_key'])
                    
                    prompt = f"""Analyze the following network security scan results and provide:
1. A brief security assessment
2. Key findings and risk level
3. Analysis of source and destination IP patterns
4. Port usage analysis and any concerning patterns
5. Specific recommendations for improving security
6. Any patterns or anomalies detected in the connections

Scan Results:
{scan_summary}

Please provide a concise but thorough analysis suitable for a security report."""
                    
                    response = client.chat.completions.create(
                        model=self.settings['openai_model'],
                        messages=[
                            {"role": "system", "content": "You are a network security expert analyzing IDS scan results with focus on IP and port patterns."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.7,
                        max_tokens=1000
                    )
                    
                    analysis_result = response.choices[0].message.content
                    
                    # Close progress window
                    progress_window.destroy()
                    
                    # Display results
                    self.show_ai_analysis_results(analysis_result)
                    
                except Exception as e:
                    progress_window.destroy()
                    messagebox.showerror("AI Analysis Error", f"Failed to perform AI analysis:\n{str(e)}")
            
            # Start analysis in thread
            analysis_thread = threading.Thread(target=analyze, daemon=True)
            analysis_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initiate AI analysis: {str(e)}")
    
    def prepare_scan_summary(self):
        """Prepare a summary of scan results for AI analysis"""
        summary = f"""
Network Scan Summary:
- Monitoring Duration: {self.stats_labels['uptime'].cget('text')}
- Total Connections Observed: {len(self.connection_history)}
- Unique Source IPs: {len(self.network_stats['unique_source_ips'])}
- Unique Destination IPs: {len(self.network_stats['unique_dest_ips'])}
- Active Ports Used: {len(self.network_stats['port_activity'])}
- Suspicious Connections: {self.network_stats['suspicious_connections']}
- Total Alerts Generated: {self.network_stats['alerts_count']}
- Data Sent: {self.network_stats['total_bytes_sent'] / (1024*1024):.2f} MB
- Data Received: {self.network_stats['total_bytes_recv'] / (1024*1024):.2f} MB

Alert Breakdown:
"""
        # Count alerts by severity
        severity_counts = Counter(alert['severity'] for alert in self.alerts)
        for severity, count in severity_counts.items():
            summary += f"- {severity}: {count} alerts\n"
        
        # Add top source IPs
        if self.network_stats['unique_source_ips']:
            summary += f"\nTop Source IPs:\n"
            for ip in list(self.network_stats['unique_source_ips'])[:10]:
                summary += f"- {ip}\n"
        
        # Add top destination IPs
        if self.network_stats['unique_dest_ips']:
            summary += f"\nTop Destination IPs:\n"
            for ip in list(self.network_stats['unique_dest_ips'])[:10]:
                summary += f"- {ip}\n"
        
        # Add port activity
        if self.network_stats['port_activity']:
            summary += f"\nMost Active Ports:\n"
            sorted_ports = sorted(self.network_stats['port_activity'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]
            for port, count in sorted_ports:
                port_desc = self.get_port_description(port)
                summary += f"- Port {port} ({port_desc}): {count} connections\n"
        
        # Add recent alerts
        summary += "\nRecent Security Alerts (Last 10):\n"
        for alert in self.alerts[-10:]:
            summary += f"- [{alert['severity']}] {alert['title']}: {alert['description']}\n"
        
        # Add connection patterns
        if self.connections:
            summary += f"\nTop Remote IPs by Connection Count:\n"
            sorted_ips = sorted(self.connections.items(), 
                              key=lambda x: x[1]['count'], 
                              reverse=True)[:5]
            for ip, data in sorted_ips:
                summary += f"- {ip}: {data['count']} connections, Local ports: {data.get('local_ports', [])[:5]}\n"
        
        return summary
    
    def show_ai_analysis_results(self, analysis):
        """Display AI analysis results in a new window"""
        result_window = tk.Toplevel(self.root)
        result_window.title("🤖 AI Security Analysis Results")
        result_window.geometry("700x500")
        result_window.configure(bg='#2c3e50')
        result_window.transient(self.root)
        
        # Header
        header_frame = tk.Frame(result_window, bg='#34495e')
        header_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_frame, text="🤖 AI-Powered Security Analysis", 
                bg='#34495e', fg='white', font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Analysis text
        text_frame = tk.Frame(result_window, bg='#2c3e50')
        text_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        analysis_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, 
                                                 bg='#1a1a1a', fg='#ecf0f1',
                                                 font=('Consolas', 10))
        analysis_text.pack(fill='both', expand=True)
        analysis_text.insert(tk.END, analysis)
        analysis_text.config(state='disabled')
        
        # Buttons
        button_frame = tk.Frame(result_window, bg='#2c3e50')
        button_frame.pack(fill='x', padx=10, pady=10)
        
        def save_analysis():
            filename = f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"AI Security Analysis Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Model: {self.settings['openai_model']}\n")
                f.write("=" * 60 + "\n\n")
                f.write(analysis)
            messagebox.showinfo("Saved", f"Analysis saved to {filename}")
        
        tk.Button(button_frame, text="💾 Save Analysis", command=save_analysis,
                 bg='#27ae60', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="📋 Copy to Clipboard", 
                 command=lambda: self.root.clipboard_clear() or self.root.clipboard_append(analysis),
                 bg='#3498db', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="❌ Close", command=result_window.destroy,
                 bg='#e74c3c', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        # Add to alerts log
        self.add_alert("INFO", "🤖 AI Analysis Complete", 
                      "Security analysis performed using OpenAI")
    
    def show_settings(self):
        """Show enhanced settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Connection Monitor Settings")
        settings_window.geometry("500x700")
        settings_window.configure(bg='#2c3e50')
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Detection Settings Tab
        detection_frame = tk.Frame(notebook, bg='#2c3e50')
        notebook.add(detection_frame, text='🔍 Detection')
        
        # Settings variables
        settings_vars = {}
        
        # Max connections per IP
        frame = tk.Frame(detection_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="Max Connections per IP", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        max_conn_var = tk.StringVar(value=str(self.settings.get('max_connections_per_ip', 50)))
        settings_vars['max_connections_per_ip'] = max_conn_var
        tk.Entry(frame, textvariable=max_conn_var, font=('Arial', 10)).pack(fill='x', pady=2)
        
        # Monitor interval
        frame = tk.Frame(detection_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="Check Interval (How often to scan)", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        
        interval_frame = tk.Frame(frame, bg='#2c3e50')
        interval_frame.pack(fill='x', pady=2)
        
        monitor_interval_var = tk.StringVar(value=str(self.settings.get('monitor_interval', 2)))
        settings_vars['monitor_interval'] = monitor_interval_var
        tk.Entry(interval_frame, textvariable=monitor_interval_var, font=('Arial', 10), width=10).pack(side='left', padx=(0, 5))
        
        monitor_unit_var = tk.StringVar(value=self.settings.get('monitor_interval_unit', 'seconds'))
        settings_vars['monitor_interval_unit'] = monitor_unit_var
        ttk.Combobox(interval_frame, textvariable=monitor_unit_var, 
                    values=['seconds', 'minutes', 'hours'], 
                    state='readonly', width=10).pack(side='left')
        
        # Capture duration
        frame = tk.Frame(detection_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="Total Capture Duration (How long to monitor)", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        
        duration_frame = tk.Frame(frame, bg='#2c3e50')
        duration_frame.pack(fill='x', pady=2)
        
        capture_duration_var = tk.StringVar(value=str(self.settings.get('capture_duration', 5)))
        settings_vars['capture_duration'] = capture_duration_var
        tk.Entry(duration_frame, textvariable=capture_duration_var, font=('Arial', 10), width=10).pack(side='left', padx=(0, 5))
        
        capture_unit_var = tk.StringVar(value=self.settings.get('capture_duration_unit', 'minutes'))
        settings_vars['capture_duration_unit'] = capture_unit_var
        ttk.Combobox(duration_frame, textvariable=capture_unit_var, 
                    values=['seconds', 'minutes', 'hours'], 
                    state='readonly', width=10).pack(side='left')
        
        # Suspicious ports
        frame = tk.Frame(detection_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="Suspicious Ports (comma-separated)", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        ports_var = tk.StringVar(value=','.join(map(str, self.settings['suspicious_ports'])))
        tk.Entry(frame, textvariable=ports_var, font=('Arial', 10)).pack(fill='x', pady=2)
        
        # AI Settings Tab
        ai_frame = tk.Frame(notebook, bg='#2c3e50')
        notebook.add(ai_frame, text='🤖 AI Analysis')
        
        # OpenAI API Key
        frame = tk.Frame(ai_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="OpenAI API Key", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        api_key_var = tk.StringVar(value=self.settings.get('openai_api_key', ''))
        settings_vars['openai_api_key'] = api_key_var
        api_entry = tk.Entry(frame, textvariable=api_key_var, font=('Arial', 10), show='*')
        api_entry.pack(fill='x', pady=2)
        
        # Model selection - Updated with new models
        frame = tk.Frame(ai_frame, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=10)
        tk.Label(frame, text="AI Model", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        model_var = tk.StringVar(value=self.settings.get('openai_model', 'gpt-5-nano'))
        settings_vars['openai_model'] = model_var
        ttk.Combobox(frame, textvariable=model_var, 
                    values=['gpt-5-nano', 'gpt-5-mini', 'gpt-4-nano'], 
                    state='readonly').pack(fill='x', pady=2)
        
        # Auto-analyze checkbox
        auto_analyze_var = tk.BooleanVar(value=self.settings.get('auto_analyze', False))
        settings_vars['auto_analyze'] = auto_analyze_var
        tk.Checkbutton(ai_frame, text="Auto-analyze when scan completes", 
                      variable=auto_analyze_var, bg='#2c3e50', fg='#ecf0f1',
                      selectcolor='#34495e', font=('Arial', 10)).pack(padx=20, pady=10, anchor='w')
        
        # AI Info - Updated for new models
        info_text = """💡 AI Analysis Tips:
• Get your API key from platform.openai.com
• GPT-5-nano is the fastest and most efficient
• GPT-5-mini provides balanced performance
• GPT-4-nano offers compatibility mode
• Auto-analyze runs AI analysis automatically"""
        
        tk.Label(ai_frame, text=info_text, bg='#2c3e50', fg='#95a5a6', 
                font=('Arial', 9), justify='left').pack(padx=20, pady=10, anchor='w')
        
        # Save button
        def save_settings():
            try:
                # Validate and update settings
                self.settings['max_connections_per_ip'] = int(settings_vars['max_connections_per_ip'].get())
                self.settings['monitor_interval'] = float(settings_vars['monitor_interval'].get())
                self.settings['monitor_interval_unit'] = settings_vars['monitor_interval_unit'].get()
                self.settings['capture_duration'] = float(settings_vars['capture_duration'].get())
                self.settings['capture_duration_unit'] = settings_vars['capture_duration_unit'].get()
                self.settings['openai_api_key'] = settings_vars['openai_api_key'].get()
                self.settings['openai_model'] = settings_vars['openai_model'].get()
                self.settings['auto_analyze'] = settings_vars['auto_analyze'].get()
                
                # Update suspicious ports
                self.settings['suspicious_ports'] = [int(p.strip()) for p in ports_var.get().split(',') if p.strip().isdigit()]
                
                # Enable/disable AI button based on API key
                if self.settings['openai_api_key'] and HAS_OPENAI:
                    self.ai_button.config(state='normal')
                
                messagebox.showinfo("Success", "Settings saved successfully!")
                settings_window.destroy()
                
            except ValueError as e:
                messagebox.showerror("Error", f"Please enter valid values: {str(e)}")
        
        button_frame = tk.Frame(settings_window, bg='#2c3e50')
        button_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Button(button_frame, text="💾 Save", command=save_settings, 
                 bg='#27ae60', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(button_frame, text="❌ Cancel", command=settings_window.destroy, 
                 bg='#e74c3c', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(tk.END, "🗑️ Alerts cleared\n")
        self.alerts_text.insert(tk.END, "=" * 70 + "\n\n")
    
    def export_report(self):
        """Export enhanced security report with IP/Port details"""
        try:
            report_content = self.generate_report()
            
            # Save to file
            filename = f"connection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            # Show success message
            result = messagebox.askyesno("Report Exported", f"Report saved as {filename}\n\nWould you like to open it?")
            if result:
                if platform.system() == 'Windows':
                    os.startfile(filename)
                elif platform.system() == 'Darwin':
                    subprocess.run(['open', filename])
                else:
                    subprocess.run(['xdg-open', filename])
                    
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    def generate_report(self, use_emojis=True):
        """Generate a comprehensive security report with detailed connection information"""
        interval_text = f"{self.settings['monitor_interval']} {self.settings['monitor_interval_unit']}"
        duration_text = f"{self.settings['capture_duration']} {self.settings['capture_duration_unit']}"
        
        report = f"""
NETWORK CONNECTION MONITORING REPORT
=====================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Monitoring Duration: {self.stats_labels['uptime'].cget('text')}
Configured Duration: {duration_text}
Check Interval: {interval_text}

SUMMARY STATISTICS
------------------
Total Network Connections: {self.network_stats['total_connections']}
Unique Source IPs: {len(self.network_stats['unique_source_ips'])}
Unique Destination IPs: {len(self.network_stats['unique_dest_ips'])}
Active Ports Used: {len(self.network_stats['port_activity'])}
Suspicious Activity Detected: {self.network_stats['suspicious_connections']}
Total Alerts Generated: {self.network_stats['alerts_count']}
Data Sent: {self.network_stats['total_bytes_sent'] / (1024*1024):.2f} MB
Data Received: {self.network_stats['total_bytes_recv'] / (1024*1024):.2f} MB

SOURCE IP ADDRESSES
-------------------
"""
        # List source IPs
        if self.network_stats['unique_source_ips']:
            for ip in sorted(self.network_stats['unique_source_ips']):
                report += f"  {ip}\n"
        else:
            report += "  No source IPs recorded\n"
        
        report += f"""
DESTINATION IP ADDRESSES
------------------------
"""
        # List destination IPs
        if self.network_stats['unique_dest_ips']:
            for ip in sorted(self.network_stats['unique_dest_ips']):
                report += f"  {ip}\n"
        else:
            report += "  No destination IPs recorded\n"
        
        report += f"""
PORT ACTIVITY ANALYSIS
----------------------
"""
        if self.network_stats['port_activity']:
            sorted_ports = sorted(self.network_stats['port_activity'].items(), 
                                key=lambda x: x[1], reverse=True)
            for port, count in sorted_ports[:20]:
                port_desc = self.get_port_description(port)
                suspicious = " [SUSPICIOUS]" if port in self.settings['suspicious_ports'] else ""
                report += f"  Port {port:5d} ({port_desc:20s}): {count:4d} connections{suspicious}\n"
        else:
            report += "  No port activity recorded\n"
        
        report += f"""
SECURITY ALERTS
---------------
"""
        
        # Add alerts
        if self.alerts:
            for alert in self.alerts:
                report += f"\n[{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] {alert['severity']}\n"
                report += f"Title: {alert['title']}\n"
                report += f"Description: {alert['description']}\n"
                report += "-" * 50 + "\n"
        else:
            report += "No alerts recorded during this session.\n"
        
        # Add connection details
        report += f"""

CONNECTION ANALYSIS
-------------------
"""
        if self.connections:
            report += f"Total unique remote IPs detected: {len(self.connections)}\n\n"
            report += "Top Connections by Volume:\n"
            sorted_ips = sorted(self.connections.items(), 
                              key=lambda x: x[1]['count'], 
                              reverse=True)[:10]
            for ip, data in sorted_ips:
                report += f"\nRemote IP: {ip}\n"
                report += f"  Total Connections: {data['count']}\n"
                report += f"  Last Seen: {data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}\n"
                if 'local_ports' in data and data['local_ports']:
                    report += f"  Local Ports Accessed: {', '.join(map(str, data['local_ports'][:10]))}\n"
                if 'remote_ports' in data and data['remote_ports']:
                    report += f"  Remote Ports Used: {', '.join(map(str, data['remote_ports'][:10]))}\n"
        else:
            report += "No connection patterns recorded.\n"
        
        # Add recent connections
        if self.connection_history:
            report += f"""

RECENT CONNECTION SAMPLES (Last 20)
------------------------------------
"""
            for conn in self.connection_history[-20:]:
                src = f"{conn['source_ip']}:{conn['source_port']}" if conn['source_ip'] else "N/A"
                dst = f"{conn['dest_ip']}:{conn['dest_port']}" if conn['dest_ip'] else "N/A"
                report += f"{conn['timestamp'].strftime('%H:%M:%S')} | {src:21s} → {dst:21s} | {conn['protocol']:4s} | {conn['status']:12s} | {conn['process']}\n"
        
        report += f"""

DETECTION SETTINGS
------------------
Max Connections per IP: {self.settings['max_connections_per_ip']}
Monitor Interval: {interval_text}
Capture Duration: {duration_text}
Suspicious Ports: {', '.join(map(str, self.settings['suspicious_ports']))}
AI Analysis: {'Enabled' if self.settings.get('openai_api_key') else 'Disabled'}
AI Model: {self.settings.get('openai_model', 'Not configured')}

SYSTEM INFORMATION
------------------
Platform: {platform.system()} {platform.release()}
Python Version: {platform.python_version()}
NIDS Version: 3.1 (Enhanced IP/Port Monitoring)

Report End
==========
"""
        return report
    
    def run(self):
        """Start the GUI application"""
        try:
            print("🛡️ Starting Network Connection Monitor...")
            print("📱 GUI interface will open shortly...")
            self.root.mainloop()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
        except Exception as e:
            print(f"❌ Error: {e}")
            messagebox.showerror("Application Error", f"An error occurred: {str(e)}")


def check_dependencies():
    """Check and inform about dependencies"""
    missing = []
    
    try:
        import psutil
    except ImportError:
        missing.append("psutil")
    
    if missing:
        print("❌ Missing required dependencies:")
        for dep in missing:
            print(f"   - {dep}")
        print("\n📥 Install with: pip install " + " ".join(missing))
        return False
    
    # Check optional dependencies
    if not HAS_OPENAI:
        print("🤖 OpenAI library not found (AI analysis disabled)")
        print("📥 Install with: pip install openai")
    
    if not HAS_PLOTTING:
        print("📊 Plotting libraries not found (visualizations disabled)")
        print("📥 Install with: pip install pandas matplotlib seaborn")
    
    return True


def main():
    """Main function"""
    print("""
╔═══════════════════════════════════════════╗
║   🛡️  NETWORK CONNECTION MONITOR v3.1     ║
║                                           ║
║   ✅ No WinPcap/Npcap required            ║
║   🖥️  IP & Port Tracking                  ║
║   🌐 Source/Destination Monitoring        ║
║   📊 Real-time Connection Analysis        ║
║   🤖 AI-powered Security Analysis         ║
║   ⏱️  Fixed Duration Control              ║
╚═══════════════════════════════════════════╝
""")
    
    # Check dependencies
    if not check_dependencies():
        input("Press Enter to exit...")
        return
    
    print("🚀 All required dependencies available!")
    print("🔧 No special drivers or admin privileges required!")
    print("📱 Starting enhanced GUI interface...\n")
    
    try:
        # Create and run the NIDS
        nids = FriendlyNIDS()
        nids.run()
        
    except Exception as e:
        print(f"❌ Error starting NIDS: {e}")
        messagebox.showerror("Startup Error", f"Failed to start NIDS: {str(e)}")
    
    print("\n👋 Thank you for using Network Connection Monitor!")


if __name__ == "__main__":
    main()