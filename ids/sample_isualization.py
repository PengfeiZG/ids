#!/usr/bin/env python3
"""
Generate Sample NIDS Visualizations
Creates realistic-looking network analysis visualizations with sample data
No actual packet capture required - great for testing and demos
"""

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import json

def generate_sample_data(num_packets=5000, duration_minutes=10):
    """Generate realistic sample network data"""
    
    print("🎲 Generating sample network data...")
    
    # Common IPs for simulation
    internal_ips = [f"192.168.1.{i}" for i in range(100, 110)]
    external_ips = [
        "8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.140",
        "52.84.228.25", "172.217.14.100", "31.13.66.35", "20.205.243.166"
    ]
    
    # Common ports and their services
    port_services = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
        21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
        3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP", 445: "SMB"
    }
    
    # Generate packets
    packets = []
    start_time = datetime.now() - timedelta(minutes=duration_minutes)
    
    for i in range(num_packets):
        # Time distribution (more activity during certain periods)
        time_offset = random.random() * duration_minutes * 60
        if random.random() > 0.7:  # Create traffic spikes
            time_offset = random.gauss(duration_minutes * 30, 60)
            time_offset = max(0, min(time_offset, duration_minutes * 60))
        
        packet = {
            'timestamp': start_time + timedelta(seconds=time_offset),
            'src_ip': random.choice(internal_ips) if random.random() > 0.3 else random.choice(external_ips),
            'dst_ip': random.choice(external_ips) if random.random() > 0.3 else random.choice(internal_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(list(port_services.keys())) if random.random() > 0.2 else random.randint(1, 65535),
            'protocol': random.choices(['TCP', 'UDP', 'ICMP', 'Other'], weights=[60, 25, 10, 5])[0],
            'size': int(random.lognormvariate(6, 2)),  # Realistic packet size distribution
            'flags': random.choice(['S', 'SA', 'A', 'F', 'R', 'PA']) if random.random() > 0.3 else None
        }
        packets.append(packet)
    
    # Add some "suspicious" activity
    suspicious_ips = random.sample(internal_ips, 2)
    
    # Simulate port scan
    for i in range(50):
        scan_packet = {
            'timestamp': start_time + timedelta(seconds=random.uniform(0, 60)),
            'src_ip': suspicious_ips[0],
            'dst_ip': random.choice(internal_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.randint(1, 1000),
            'protocol': 'TCP',
            'size': 60,
            'flags': 'S'
        }
        packets.append(scan_packet)
    
    # Simulate SYN flood
    for i in range(200):
        flood_packet = {
            'timestamp': start_time + timedelta(seconds=random.uniform(120, 180)),
            'src_ip': suspicious_ips[1],
            'dst_ip': internal_ips[0],
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'protocol': 'TCP',
            'size': 60,
            'flags': 'S'
        }
        packets.append(flood_packet)
    
    df = pd.DataFrame(packets)
    df = df.sort_values('timestamp')
    
    print(f"✅ Generated {len(df)} packets with suspicious activity")
    return df, port_services

def create_dashboard(df, port_services):
    """Create interactive dashboard with multiple visualizations"""
    
    print("📊 Creating interactive dashboard...")
    
    # Create figure with subplots
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=(
            'Packet Rate Over Time', 
            'Protocol Distribution',
            'Top Source IPs', 
            'Port Activity',
            'Packet Size Distribution',
            'Network Activity Timeline'
        ),
        specs=[
            [{'type': 'scatter'}, {'type': 'pie'}],
            [{'type': 'bar'}, {'type': 'bar'}],
            [{'type': 'histogram'}, {'type': 'scatter'}]
        ],
        vertical_spacing=0.12,
        horizontal_spacing=0.15
    )
    
    # 1. Packet rate over time
    df['timestamp_rounded'] = df['timestamp'].dt.floor('10S')
    packet_rate = df.groupby('timestamp_rounded').size().reset_index(name='count')
    
    fig.add_trace(
        go.Scatter(
            x=packet_rate['timestamp_rounded'],
            y=packet_rate['count'],
            mode='lines',
            name='Packets/10s',
            line=dict(color='#667eea', width=2),
            fill='tozeroy',
            fillcolor='rgba(102, 126, 234, 0.2)'
        ),
        row=1, col=1
    )
    
    # 2. Protocol distribution
    protocol_counts = df['protocol'].value_counts()
    colors = ['#667eea', '#764ba2', '#f093fb', '#ffa502']
    
    fig.add_trace(
        go.Pie(
            labels=protocol_counts.index,
            values=protocol_counts.values,
            name='Protocols',
            marker=dict(colors=colors),
            hole=0.3
        ),
        row=1, col=2
    )
    
    # 3. Top source IPs
    top_sources = df['src_ip'].value_counts().head(10)
    
    fig.add_trace(
        go.Bar(
            x=top_sources.values,
            y=top_sources.index,
            orientation='h',
            name='Source IPs',
            marker=dict(
                color=top_sources.values,
                colorscale='Viridis',
                showscale=False
            )
        ),
        row=2, col=1
    )
    
    # 4. Port activity
    top_ports = df['dst_port'].value_counts().head(10)
    port_labels = [f"{port}\n({port_services.get(port, 'Unknown')})" for port in top_ports.index]
    
    fig.add_trace(
        go.Bar(
            x=port_labels,
            y=top_ports.values,
            name='Port Activity',
            marker=dict(
                color=top_ports.values,
                colorscale='Plasma',
                showscale=False
            )
        ),
        row=2, col=2
    )
    
    # 5. Packet size distribution
    fig.add_trace(
        go.Histogram(
            x=df['size'],
            nbinsx=50,
            name='Packet Sizes',
            marker=dict(color='#667eea'),
            showlegend=False
        ),
        row=3, col=1
    )
    
    # 6. Network activity timeline (by protocol)
    for protocol in df['protocol'].unique():
        protocol_df = df[df['protocol'] == protocol]
        fig.add_trace(
            go.Scatter(
                x=protocol_df['timestamp'],
                y=[protocol] * len(protocol_df),
                mode='markers',
                name=protocol,
                marker=dict(size=3),
                showlegend=False
            ),
            row=3, col=2
        )
    
    # Update layout
    fig.update_layout(
        height=1000,
        showlegend=False,
        title_text="<b>Network Traffic Analysis Dashboard</b>",
        title_font_size=24,
        title_x=0.5,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white',
        font=dict(family="Arial, sans-serif", size=12),
        margin=dict(t=80, b=40, l=40, r=40)
    )
    
    # Update axes
    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0,0,0,0.05)')
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0,0,0,0.05)')
    
    # Save dashboard
    fig.write_html("sample_dashboard.html")
    print("✅ Dashboard saved as: sample_dashboard.html")
    
    return fig

def create_heatmap(df):
    """Create network interaction heatmap"""
    
    print("🗺️  Creating interaction heatmap...")
    
    # Create interaction matrix
    interactions = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
    
    # Get top IPs for cleaner visualization
    top_ips = pd.concat([df['src_ip'], df['dst_ip']]).value_counts().head(20).index
    interactions_filtered = interactions[
        interactions['src_ip'].isin(top_ips) & 
        interactions['dst_ip'].isin(top_ips)
    ]
    
    pivot = interactions_filtered.pivot(
        index='src_ip', 
        columns='dst_ip', 
        values='count'
    ).fillna(0)
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=pivot.columns,
        y=pivot.index,
        colorscale='Viridis',
        text=pivot.values.astype(int),
        texttemplate='%{text}',
        textfont={"size": 8},
        colorbar=dict(title="Packets")
    ))
    
    fig.update_layout(
        title='<b>Network Interaction Heatmap</b><br><sub>Packet flow between IP addresses</sub>',
        xaxis_title='Destination IP',
        yaxis_title='Source IP',
        height=700,
        width=900,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white',
        font=dict(family="Arial, sans-serif", size=12),
        title_x=0.5,
        title_font_size=20
    )
    
    fig.write_html("sample_heatmap.html")
    print("✅ Heatmap saved as: sample_heatmap.html")
    
    return fig

def create_alert_timeline(df):
    """Create alert timeline visualization"""
    
    print("⚠️  Creating alert timeline...")
    
    # Generate sample alerts
    alerts = []
    
    # Port scan alert
    port_scan_time = df['timestamp'].min() + timedelta(seconds=30)
    alerts.append({
        'time': port_scan_time,
        'type': 'PORT_SCAN',
        'severity': 2,
        'description': 'Port scanning detected from 192.168.1.105'
    })
    
    # SYN flood alert
    syn_flood_time = df['timestamp'].min() + timedelta(seconds=150)
    alerts.append({
        'time': syn_flood_time,
        'type': 'SYN_FLOOD',
        'severity': 3,
        'description': 'SYN flood attack from 192.168.1.106'
    })
    
    # High packet rate alerts
    for i in range(3):
        alert_time = df['timestamp'].min() + timedelta(seconds=random.randint(200, 500))
        alerts.append({
            'time': alert_time,
            'type': 'HIGH_PACKET_RATE',
            'severity': 2,
            'description': f'Unusual packet rate from {random.choice(df["src_ip"].unique())}'
        })
    
    # Suspicious port alerts
    for i in range(2):
        alert_time = df['timestamp'].min() + timedelta(seconds=random.randint(100, 400))
        alerts.append({
            'time': alert_time,
            'type': 'SUSPICIOUS_PORT',
            'severity': 3,
            'description': f'Connection to port {random.choice([445, 3389, 23])}'
        })
    
    alerts_df = pd.DataFrame(alerts).sort_values('time')
    
    # Create timeline
    fig = go.Figure()
    
    # Add alerts as scatter points
    colors = {1: 'blue', 2: 'orange', 3: 'red'}
    severity_names = {1: 'Low', 2: 'Medium', 3: 'High'}
    
    for severity in [1, 2, 3]:
        severity_alerts = alerts_df[alerts_df['severity'] == severity]
        if not severity_alerts.empty:
            fig.add_trace(go.Scatter(
                x=severity_alerts['time'],
                y=severity_alerts['type'],
                mode='markers',
                name=f'{severity_names[severity]} Severity',
                marker=dict(
                    size=15,
                    color=colors[severity],
                    symbol='diamond',
                    line=dict(width=2, color='white')
                ),
                text=severity_alerts['description'],
                hovertemplate='<b>%{y}</b><br>%{text}<br>Time: %{x}<extra></extra>'
            ))
    
    # Add background packet rate
    packet_rate = df.groupby(pd.Grouper(key='timestamp', freq='30S')).size()
    
    fig.add_trace(go.Scatter(
        x=packet_rate.index,
        y=packet_rate.values / packet_rate.max() * 5,  # Scale to fit
        mode='lines',
        name='Packet Rate',
        line=dict(color='lightgray', width=1),
        fill='tozeroy',
        fillcolor='rgba(200, 200, 200, 0.2)',
        yaxis='y2',
        hovertemplate='Packets: %{y:.0f}<extra></extra>'
    ))
    
    fig.update_layout(
        title='<b>Security Alert Timeline</b><br><sub>Detected threats and anomalies</sub>',
        xaxis_title='Time',
        yaxis_title='Alert Type',
        yaxis2=dict(
            title='Packet Rate',
            overlaying='y',
            side='right',
            range=[0, 6],
            showgrid=False
        ),
        height=500,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white',
        font=dict(family="Arial, sans-serif", size=12),
        title_x=0.5,
        title_font_size=20,
        hovermode='x unified',
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5
        )
    )
    
    fig.write_html("sample_alerts.html")
    print("✅ Alert timeline saved as: sample_alerts.html")
    
    return fig, alerts_df

def create_statistics_report(df, alerts_df):
    """Generate statistics report"""
    
    print("📝 Creating statistics report...")
    
    stats = {
        'total_packets': len(df),
        'unique_src_ips': df['src_ip'].nunique(),
        'unique_dst_ips': df['dst_ip'].nunique(),
        'total_bytes': df['size'].sum(),
        'avg_packet_size': df['size'].mean(),
        'duration': (df['timestamp'].max() - df['timestamp'].min()).total_seconds(),
        'protocols': df['protocol'].value_counts().to_dict(),
        'top_talker': df['src_ip'].value_counts().index[0],
        'top_destination': df['dst_ip'].value_counts().index[0],
        'alerts_generated': len(alerts_df),
        'high_severity_alerts': len(alerts_df[alerts_df['severity'] == 3])
    }
    
    # Create HTML report
    html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Analysis Report</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
                margin: 0;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }}
            h1 {{
                color: #333;
                text-align: center;
                margin-bottom: 30px;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }}
            .stat-value {{
                font-size: 2em;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            .stat-label {{
                font-size: 0.9em;
                opacity: 0.9;
            }}
            .section {{
                margin: 30px 0;
            }}
            .section h2 {{
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background: #f8f9fa;
                font-weight: 600;
            }}
            .alert-high {{
                color: #dc3545;
                font-weight: bold;
            }}
            .alert-medium {{
                color: #ffc107;
                font-weight: bold;
            }}
            .alert-low {{
                color: #28a745;
            }}
            .timestamp {{
                text-align: center;
                color: #666;
                margin-top: 30px;
                font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Network Security Analysis Report</h1>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_packets']:,}</div>
                    <div class="stat-label">Total Packets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['unique_src_ips'] + stats['unique_dst_ips']}</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total_bytes'] / (1024*1024):.2f} MB</div>
                    <div class="stat-label">Data Transferred</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['alerts_generated']}</div>
                    <div class="stat-label">Security Alerts</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Protocol Distribution</h2>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Packet Count</th>
                        <th>Percentage</th>
                    </tr>
    """
    
    for proto, count in stats['protocols'].items():
        percentage = (count / stats['total_packets']) * 100
        html_report += f"""
                    <tr>
                        <td>{proto}</td>
                        <td>{count:,}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
        """
    
    html_report += f"""
                </table>
            </div>
            
            <div class="section">
                <h2>Recent Security Alerts</h2>
                <table>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
    """
    
    severity_classes = {1: 'alert-low', 2: 'alert-medium', 3: 'alert-high'}
    severity_names = {1: 'Low', 2: 'Medium', 3: 'High'}
    
    for _, alert in alerts_df.iterrows():
        html_report += f"""
                    <tr>
                        <td>{alert['time'].strftime('%H:%M:%S')}</td>
                        <td>{alert['type']}</td>
                        <td class="{severity_classes[alert['severity']]}">{severity_names[alert['severity']]}</td>
                        <td>{alert['description']}</td>
                    </tr>
        """
    
    html_report += f"""
                </table>
            </div>
            
            <div class="timestamp">
                Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                Analysis duration: {stats['duration']:.0f} seconds
            </div>
        </div>
    </body>
    </html>
    """
    
    with open("sample_report.html", "w") as f:
        f.write(html_report)
    
    print("✅ Report saved as: sample_report.html")
    
    return stats

def main():
    """Main function to generate all visualizations"""
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   NIDS Visualization Generator            ║
    ║   Creating Sample Network Visualizations  ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Check required libraries
    required = ['pandas', 'plotly', 'numpy']
    missing = []
    
    for lib in required:
        try:
            __import__(lib)
        except ImportError:
            missing.append(lib)
    
    if missing:
        print(f"\n❌ Missing required libraries: {', '.join(missing)}")
        print(f"Install with: pip install {' '.join(missing)}")
        return
    
    print("\n🚀 Starting visualization generation...\n")
    
    # Generate sample data
    df, port_services = generate_sample_data(num_packets=5000, duration_minutes=10)
    
    # Create visualizations
    dashboard = create_dashboard(df, port_services)
    heatmap = create_heatmap(df)
    timeline, alerts_df = create_alert_timeline(df)
    stats = create_statistics_report(df, alerts_df)
    
    print("\n" + "="*50)
    print("✨ VISUALIZATION GENERATION COMPLETE!")
    print("="*50)
    
    print("\n📁 Generated Files:")
    print("  • sample_dashboard.html - Main analytics dashboard")
    print("  • sample_heatmap.html   - Network interaction heatmap")
    print("  • sample_alerts.html    - Security alert timeline")
    print("  • sample_report.html    - Statistics report")
    
    print("\n📊 Statistics Summary:")
    print(f"  • Total Packets: {stats['total_packets']:,}")
    print(f"  • Unique IPs: {stats['unique_src_ips'] + stats['unique_dst_ips']}")
    print(f"  • Data Volume: {stats['total_bytes'] / (1024*1024):.2f} MB")
    print(f"  • Security Alerts: {stats['alerts_generated']}")
    print(f"  • High Severity: {stats['high_severity_alerts']}")
    
    print("\n👀 To view the visualizations:")
    print("  1. Open any of the HTML files in your web browser")
    print("  2. Double-click the file or right-click → Open with → Browser")
    print("  3. All visualizations are interactive - hover, zoom, and click!")
    
    print("\n💡 Tips:")
    print("  • The dashboard shows multiple views of network activity")
    print("  • The heatmap reveals communication patterns")
    print("  • The alert timeline shows security events over time")
    print("  • All charts are interactive - try hovering and clicking!")
    
    print("\n✅ Success! Your sample visualizations are ready to view.")

if __name__ == "__main__":
    main()