#!/usr/bin/env python3
"""
Friendly Network Intrusion Detection System (NIDS)
No WinPcap/Npcap required - Works on all platforms!
User-friendly GUI interface with real-time monitoring

Author: Network Security Tool v2.0
Features: GUI Interface, Cross-platform, No special drivers needed
"""

import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import webbrowser

# Core monitoring (no special drivers needed)
import psutil
import socket
import subprocess
import platform

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
    """User-friendly Network IDS with GUI - No drivers required!"""
    
    def __init__(self):
        """Initialize the friendly NIDS"""
        self.running = False
        self.monitoring_thread = None
        self.alerts = []
        self.connections = {}
        self.network_stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'total_bytes_sent': 0,
            'total_bytes_recv': 0,
            'alerts_count': 0
        }
        
        # Detection settings (user-friendly)
        self.settings = {
            'max_connections_per_ip': 50,
            'suspicious_ports': [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6666, 6667, 31337],
            'monitor_interval': 2,  # Base value
            'monitor_interval_unit': 'seconds',  # Unit for monitor interval
            'max_data_transfer_mb': 100,  # MB per minute per IP
            'alert_retention_value': 24,  # Base value for alert retention
            'alert_retention_unit': 'hours'  # Unit for alert retention
        }
        
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
        
        self.setup_gui()
    
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
        """Create the user-friendly GUI"""
        self.root = tk.Tk()
        self.root.title("🛡️ Friendly Network IDS - Protecting Your System")
        self.root.geometry("1000x700")
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
        self.create_alerts_panel()
        self.create_details_panel()
        
        # Status update queue for thread safety
        self.status_queue = queue.Queue()
        self.root.after(100, self.process_status_updates)
    
    def create_header(self):
        """Create the header section"""
        header_frame = tk.Frame(self.root, bg='#34495e', height=80)
        header_frame.pack(fill='x', padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        title_label = ttk.Label(header_frame, text="🛡️ Network Intrusion Detection System", style='Title.TLabel')
        title_label.pack(pady=15)
        
        subtitle_label = ttk.Label(header_frame, text="Real-time network monitoring • No special drivers required", style='Status.TLabel')
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
        
        # Export button
        export_button = tk.Button(
            control_frame, 
            text="📊 Export Report", 
            command=self.export_report,
            bg='#9b59b6', 
            fg='white', 
            font=('Arial', 10),
            padx=15, 
            pady=5
        )
        export_button.pack(side='left', padx=5)
        
        # Clear alerts button
        clear_button = tk.Button(
            control_frame, 
            text="🗑️ Clear Alerts", 
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
    
    def create_status_dashboard(self):
        """Create the status dashboard"""
        dashboard_frame = tk.LabelFrame(self.root, text="📊 Network Status Dashboard", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
        dashboard_frame.pack(fill='x', padx=10, pady=5)
        
        # Create stats grid
        stats_frame = tk.Frame(dashboard_frame, bg='#2c3e50')
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        # Stats labels
        self.stats_labels = {}
        stats_info = [
            ('connections', '🔗 Active Connections', '0'),
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
    
    def create_alerts_panel(self):
        """Create the alerts panel"""
        alerts_frame = tk.LabelFrame(self.root, text="🚨 Security Alerts", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
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
        self.alerts_text.insert(tk.END, "🛡️ Network IDS Ready - Click 'Start Monitoring' to begin\n")
        self.alerts_text.insert(tk.END, "=" * 60 + "\n\n")
    
    def create_details_panel(self):
        """Create the details panel"""
        details_frame = tk.LabelFrame(self.root, text="📋 Connection Details", bg='#2c3e50', fg='white', font=('Arial', 12, 'bold'))
        details_frame.pack(fill='x', padx=10, pady=5)
        
        # Create Treeview for connection details
        columns = ('Time', 'Local Address', 'Remote Address', 'Status', 'Process')
        self.details_tree = ttk.Treeview(details_frame, columns=columns, show='headings', height=6)
        
        # Configure columns
        for col in columns:
            self.details_tree.heading(col, text=col)
            self.details_tree.column(col, width=150)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(details_frame, orient='vertical', command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.details_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side='right', fill='y', padx=(0, 10), pady=10)
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if not self.running:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start the monitoring process"""
        self.running = True
        self.start_time = datetime.now()
        self.start_button.config(text="🛑 Stop Monitoring", bg='#e74c3c')
        self.status_label.config(text="🟢 Monitoring Active")
        
        # Clear previous data
        self.alerts.clear()
        self.connections.clear()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        interval_text = f"{self.settings['monitor_interval']} {self.settings['monitor_interval_unit']}"
        self.add_alert("INFO", "🚀 Network monitoring started", f"System is now actively monitoring network connections every {interval_text}")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.running = False
        self.start_button.config(text="🚀 Start Monitoring", bg='#27ae60')
        self.status_label.config(text="⚫ Stopped")
        
        self.add_alert("INFO", "🛑 Network monitoring stopped", "Monitoring session ended")
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.check_network_connections()
                self.update_statistics()
                # Use converted interval in seconds
                time.sleep(self.get_monitor_interval_seconds())
            except Exception as e:
                self.add_alert("ERROR", "🔥 Monitoring Error", f"Error in monitoring loop: {str(e)}")
                break
    
    def check_network_connections(self):
        """Check current network connections for suspicious activity"""
        try:
            current_connections = psutil.net_connections(kind='inet')
            current_time = datetime.now()
            
            # Group connections by remote IP
            ip_connections = defaultdict(list)
            
            for conn in current_connections:
                if conn.raddr:  # Has remote address
                    remote_ip = conn.raddr.ip
                    ip_connections[remote_ip].append(conn)
            
            # Analyze each IP
            for remote_ip, conns in ip_connections.items():
                self.analyze_ip_connections(remote_ip, conns, current_time)
            
            # Update connection details in GUI
            self.update_connection_details(current_connections)
            
        except Exception as e:
            self.add_alert("ERROR", "Connection Check Failed", f"Could not check connections: {str(e)}")
    
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
                self.add_alert(
                    "HIGH", 
                    f"🔍 Suspicious Port Access", 
                    f"Connection to {port_name} from {remote_ip}"
                )
        
        # Track connection patterns
        self.connections[remote_ip] = {
            'count': conn_count,
            'last_seen': current_time,
            'ports': [conn.laddr.port for conn in connections if conn.laddr]
        }
    
    def update_connection_details(self, connections):
        """Update the connection details tree"""
        # Clear existing items
        for item in self.details_tree.get_children():
            self.details_tree.delete(item)
        
        # Add current connections (limit to last 50 for performance)
        for i, conn in enumerate(connections[-50:]):
            try:
                # Get process name
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else "Unknown"
                except:
                    process_name = "Unknown"
                
                # Format addresses
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                # Insert into tree
                self.details_tree.insert('', 'end', values=(
                    datetime.now().strftime('%H:%M:%S'),
                    local_addr,
                    remote_addr,
                    conn.status,
                    process_name
                ))
            except:
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
            if hasattr(self, 'start_time'):
                uptime = datetime.now() - self.start_time
                uptime_str = str(uptime).split('.')[0]  # Remove microseconds
            else:
                uptime_str = "00:00:00"
            
            # Queue stats update for main thread
            self.status_queue.put({
                'type': 'stats_update',
                'data': {
                    'connections': str(self.network_stats['total_connections']),
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
                
                except queue.Empty:
                    break
        except:
            pass
        
        # Schedule next update
        self.root.after(100, self.process_status_updates)
    
    def show_settings(self):
        """Show settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ NIDS Settings")
        settings_window.geometry("450x600")
        settings_window.configure(bg='#2c3e50')
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Settings form
        tk.Label(settings_window, text="⚙️ Detection Settings", bg='#2c3e50', fg='white', font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Settings variables
        settings_vars = {}
        
        # Max connections per IP
        frame = tk.Frame(settings_window, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=5)
        tk.Label(frame, text="Max Connections per IP", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        max_conn_var = tk.StringVar(value=str(self.settings.get('max_connections_per_ip', 50)))
        settings_vars['max_connections_per_ip'] = max_conn_var
        entry = tk.Entry(frame, textvariable=max_conn_var, font=('Arial', 10))
        entry.pack(fill='x', pady=(2, 10))
        
        # Monitor interval with unit selector
        frame = tk.Frame(settings_window, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=5)
        tk.Label(frame, text="Monitor Interval", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        
        interval_frame = tk.Frame(frame, bg='#2c3e50')
        interval_frame.pack(fill='x', pady=(2, 10))
        
        monitor_interval_var = tk.StringVar(value=str(self.settings.get('monitor_interval', 2)))
        settings_vars['monitor_interval'] = monitor_interval_var
        interval_entry = tk.Entry(interval_frame, textvariable=monitor_interval_var, font=('Arial', 10), width=10)
        interval_entry.pack(side='left', padx=(0, 5))
        
        # Unit dropdown for monitor interval
        monitor_unit_var = tk.StringVar(value=self.settings.get('monitor_interval_unit', 'seconds'))
        settings_vars['monitor_interval_unit'] = monitor_unit_var
        monitor_unit_combo = ttk.Combobox(interval_frame, textvariable=monitor_unit_var, 
                                         values=['seconds', 'minutes', 'hours'], 
                                         state='readonly', width=10)
        monitor_unit_combo.pack(side='left')
        
        # Max data transfer
        frame = tk.Frame(settings_window, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=5)
        tk.Label(frame, text="Max Data Transfer (MB/min)", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        max_data_var = tk.StringVar(value=str(self.settings.get('max_data_transfer_mb', 100)))
        settings_vars['max_data_transfer_mb'] = max_data_var
        entry = tk.Entry(frame, textvariable=max_data_var, font=('Arial', 10))
        entry.pack(fill='x', pady=(2, 10))
        
        # Alert retention with unit selector
        frame = tk.Frame(settings_window, bg='#2c3e50')
        frame.pack(fill='x', padx=20, pady=5)
        tk.Label(frame, text="Alert Retention", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w')
        
        retention_frame = tk.Frame(frame, bg='#2c3e50')
        retention_frame.pack(fill='x', pady=(2, 10))
        
        alert_retention_var = tk.StringVar(value=str(self.settings.get('alert_retention_value', 24)))
        settings_vars['alert_retention_value'] = alert_retention_var
        retention_entry = tk.Entry(retention_frame, textvariable=alert_retention_var, font=('Arial', 10), width=10)
        retention_entry.pack(side='left', padx=(0, 5))
        
        # Unit dropdown for alert retention
        retention_unit_var = tk.StringVar(value=self.settings.get('alert_retention_unit', 'hours'))
        settings_vars['alert_retention_unit'] = retention_unit_var
        retention_unit_combo = ttk.Combobox(retention_frame, textvariable=retention_unit_var, 
                                           values=['seconds', 'minutes', 'hours', 'days'], 
                                           state='readonly', width=10)
        retention_unit_combo.pack(side='left')
        
        # Suspicious ports
        tk.Label(settings_window, text="Suspicious Ports (comma-separated)", bg='#2c3e50', fg='#ecf0f1', font=('Arial', 10)).pack(anchor='w', padx=20)
        ports_var = tk.StringVar(value=','.join(map(str, self.settings['suspicious_ports'])))
        ports_entry = tk.Entry(settings_window, textvariable=ports_var, font=('Arial', 10))
        ports_entry.pack(fill='x', padx=20, pady=(2, 20))
        
        # Info label
        info_text = """💡 Tips:
• Lower intervals = more frequent monitoring (higher CPU usage)
• Higher intervals = less frequent monitoring (lower CPU usage)
• Recommended: 2-5 seconds for active threats, 1-5 minutes for general monitoring"""
        
        info_label = tk.Label(settings_window, text=info_text, bg='#2c3e50', fg='#95a5a6', 
                             font=('Arial', 9), justify='left')
        info_label.pack(padx=20, pady=10, anchor='w')
        
        # Buttons
        button_frame = tk.Frame(settings_window, bg='#2c3e50')
        button_frame.pack(fill='x', padx=20, pady=10)
        
        def save_settings():
            try:
                # Validate and update settings
                self.settings['max_connections_per_ip'] = int(settings_vars['max_connections_per_ip'].get())
                self.settings['monitor_interval'] = float(settings_vars['monitor_interval'].get())
                self.settings['monitor_interval_unit'] = settings_vars['monitor_interval_unit'].get()
                self.settings['max_data_transfer_mb'] = int(settings_vars['max_data_transfer_mb'].get())
                self.settings['alert_retention_value'] = float(settings_vars['alert_retention_value'].get())
                self.settings['alert_retention_unit'] = settings_vars['alert_retention_unit'].get()
                
                # Update suspicious ports
                ports_str = ports_var.get()
                self.settings['suspicious_ports'] = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
                
                # Show confirmation with converted values
                interval_seconds = self.get_monitor_interval_seconds()
                retention_hours = self.get_alert_retention_hours()
                
                msg = f"Settings saved successfully!\n\n"
                msg += f"Monitor Interval: {self.settings['monitor_interval']} {self.settings['monitor_interval_unit']} "
                msg += f"({interval_seconds:.0f} seconds)\n"
                msg += f"Alert Retention: {self.settings['alert_retention_value']} {self.settings['alert_retention_unit']} "
                msg += f"({retention_hours:.1f} hours)"
                
                messagebox.showinfo("Success", msg)
                settings_window.destroy()
                
                # If monitoring is active, notify about interval change
                if self.running:
                    self.add_alert("INFO", "⚙️ Settings Updated", 
                                 f"Monitor interval changed to {self.settings['monitor_interval']} {self.settings['monitor_interval_unit']}")
                    
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numeric values")
        
        tk.Button(button_frame, text="💾 Save", command=save_settings, bg='#27ae60', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(button_frame, text="❌ Cancel", command=settings_window.destroy, bg='#e74c3c', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(tk.END, "🗑️ Alerts cleared\n")
        self.alerts_text.insert(tk.END, "=" * 60 + "\n\n")
    
    def export_report(self):
        """Export security report"""
        try:
            report_content = self.generate_report()
            
            # Save to file
            filename = f"nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            # Show success message with option to open
            result = messagebox.askyesno("Report Exported", f"Report saved as {filename}\n\nWould you like to open it?")
            if result:
                if platform.system() == 'Windows':
                    os.startfile(filename)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.run(['open', filename])
                else:  # Linux
                    subprocess.run(['xdg-open', filename])
                    
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    def generate_report(self, use_emojis=True):
        """Generate a comprehensive security report"""
        interval_text = f"{self.settings['monitor_interval']} {self.settings['monitor_interval_unit']}"
        retention_text = f"{self.settings['alert_retention_value']} {self.settings['alert_retention_unit']}"
        
        # Define symbols with or without emojis
        if use_emojis:
            shield = "🛡️"
            chart = "📊"
            alert = "🚨"
            tools = "🔧"
            search = "🔍"
            doc = "📑"
        else:
            shield = "[SHIELD]"
            chart = "[STATS]"
            alert = "[ALERT]"
            tools = "[SETTINGS]"
            search = "[SEARCH]"
            doc = "[INFO]"
        
        report = f"""
{shield} NETWORK INTRUSION DETECTION SYSTEM REPORT
=============================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Monitoring Duration: {datetime.now() - self.start_time if hasattr(self, 'start_time') else 'N/A'}

{chart} SUMMARY STATISTICS
--------------------
Total Network Connections: {self.network_stats['total_connections']}
Suspicious Activity Detected: {self.network_stats['suspicious_connections']}
Total Alerts Generated: {self.network_stats['alerts_count']}
Data Sent: {self.network_stats['total_bytes_sent'] / (1024*1024):.2f} MB
Data Received: {self.network_stats['total_bytes_recv'] / (1024*1024):.2f} MB

{alert} SECURITY ALERTS
------------------
"""
        
        # Add alerts
        if self.alerts:
            for alert in self.alerts[-20:]:  # Last 20 alerts
                report += f"\n[{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] {alert['severity']}\n"
                report += f"Title: {alert['title']}\n"
                report += f"Description: {alert['description']}\n"
                report += "-" * 50 + "\n"
        else:
            report += "No alerts recorded during this session.\n"
        
        report += f"""

{tools} DETECTION SETTINGS
--------------------
Max Connections per IP: {self.settings['max_connections_per_ip']}
Monitor Interval: {interval_text} ({self.get_monitor_interval_seconds():.0f} seconds)
Alert Retention: {retention_text} ({self.get_alert_retention_hours():.1f} hours)
Ports: {', '.join(map(str, self.settings['suspicious_ports']))}

{search} RECOMMENDATIONS
------------------
1. Review any HIGH severity alerts immediately
2. Monitor connections to suspicious ports
3. Consider blocking IPs with excessive connections
4. Keep system and security software updated
5. Regularly review and update detection settings

{doc} SYSTEM INFORMATION
--------------------
Platform: {platform.system()} {platform.release()}
Python Version: {platform.python_version()}
NIDS Version: 1.0

Report End
==========
"""
        return report
    
    def run(self):
        """Start the GUI application"""
        try:
            print("🛡️ Starting Friendly Network IDS...")
            print("📱 GUI interface will open shortly...")
            self.root.mainloop()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
        except Exception as e:
            print(f"❌ Error: {e}")
            messagebox.showerror("Application Error", f"An error occurred: {str(e)}")


def check_dependencies():
    """Check and inform about optional dependencies"""
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
    optional_missing = []
    try:
        import pandas
        import matplotlib
        import seaborn
    except ImportError:
        optional_missing.append("pandas matplotlib seaborn")
    
    if optional_missing:
        print("📊 Optional plotting libraries not found (visualizations disabled)")
        print("📥 Install with: pip install pandas matplotlib seaborn")
    
    return True


def main():
    """Main function"""
    print("""
╔═══════════════════════════════════════════╗
║   🛡️  FRIENDLY NETWORK IDS v2.0          ║
║                                           ║
║   ✅ No WinPcap/Npcap required            ║
║   🖥️  User-friendly GUI interface         ║
║   🌍 Cross-platform compatibility         ║
║   📊 Real-time network monitoring         ║
╚═══════════════════════════════════════════╝
""")
    
    # Check dependencies
    if not check_dependencies():
        input("Press Enter to exit...")
        return
    
    print("🚀 All dependencies available!")
    print("🔧 No special drivers or admin privileges required!")
    print("📱 Starting GUI interface...\n")
    
    try:
        # Create and run the NIDS
        nids = FriendlyNIDS()
        nids.run()
        
    except Exception as e:
        print(f"❌ Error starting NIDS: {e}")
        messagebox.showerror("Startup Error", f"Failed to start NIDS: {str(e)}")
    
    print("\n👋 Thank you for using Friendly Network IDS!")


if __name__ == "__main__":
    main()