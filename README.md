# Network Intrusion Detection System (NIDS) Documentation

## Overview

This Network Intrusion Detection System (NIDS) is a comprehensive security monitoring tool that captures and analyzes network traffic in real-time. It features packet capture, threat detection, a graphical user interface, and AI-powered threat summaries. The #quickstart.py# will run a very simple NIDS within terminal for quick captures without a GUI. The #veryify_pkt_capture.py# will do a simple packet capture to test if packet capture works on your system.

## Table of Contents
1. [Features](#features)
2. [System Requirements](#system-requirements)
3. [Dependencies](#dependencies)
4. [Installation Guide](#installation-guide)
5. [Usage Instructions](#usage-instructions)
6. [Configuration Options](#configuration-options)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Performance Optimization](#performance-optimization)
9. [Security Considerations](#security-considerations)
10. [File Outputs](#file-outputs)
11. [Known Limitations](#known-limitations)

---

## Features

- **Real-time packet capture and analysis**
- **Threat detection capabilities:**
  - Port scanning detection
  - SYN flood attacks
  - ICMP flood attacks
  - ARP spoofing
  - Malicious payload patterns
- **GUI with multiple tabs:**
  - Dashboard with statistics
  - Live packet monitor
  - Security alerts
  - AI analysis (requires OpenAI API key)
  - Settings configuration
- **Packet filtering** by protocol and source IP
- **Auto-scroll control** for live monitoring
- **Export capabilities** for security alerts
- **Protocol statistics** tracking (TCP, UDP, ICMP, ICMPv6, ARP, IPv6)

## System Requirements

- **Python**: Version 3.7 or higher
- **Privileges**: Administrator/root privileges (required for packet capture)
- **Network**: Active network interface access
- **Operating System**: Windows, Linux, or macOS
- **Memory**: Minimum 2GB RAM recommended
- **Storage**: 100MB for application and logs

## Dependencies

### Required Python Packages

```bash
psutil>=5.8.0
scapy>=2.4.5
openai>=1.0.0
```

### Built-in Python Modules
These are included with Python and require no additional installation:
- `tkinter` - GUI framework
- `threading` - Multi-threading support
- `queue` - Thread-safe queue implementation
- `time` - Time-related functions
- `datetime` - Date and time handling
- `collections` - Specialized container datatypes
- `json` - JSON encoder/decoder
- `re` - Regular expressions
- `ipaddress` - IP address manipulation
- `os` - Operating system interface

## Installation Guide

### Step 1: Install Python Dependencies

#### Option A: Using pip directly
```bash
# For most systems
pip install psutil scapy openai

# For systems with both Python 2 and 3
pip3 install psutil scapy openai
```

#### Option B: Using requirements.txt
Create a `requirements.txt` file with the following content:
```
psutil>=5.8.0
scapy>=2.4.5
openai>=1.0.0
```

Then install:
```bash
pip install -r requirements.txt
```

### Step 2: Platform-Specific Setup

#### Linux Setup
```bash
# Update package manager
sudo apt-get update

# Install Python tkinter and tcpdump
sudo apt-get install python3-tk tcpdump

# Optional: Grant packet capture capability without sudo
sudo setcap cap_net_raw=eip $(readlink -f $(which python3))
```

#### Windows Setup
1. **Install Npcap or WinPcap**
   - Download from: https://npcap.com/
   - Run installer with Administrator privileges
   - Select "Install Npcap in WinPcap API-compatible Mode"

2. **Verify Python Installation**
   - Ensure Python was installed with tkinter support (default)
   - Test: `python -c "import tkinter"`

#### macOS Setup
```bash
# Using Homebrew
brew install python-tk
brew install libpcap

# Grant permissions if needed
sudo chmod +r /dev/bpf*
```

### Step 3: Verify Installation
```bash
# Check all dependencies
python -c "import psutil, scapy, openai, tkinter; print('All dependencies installed successfully')"
```

## Usage Instructions

### Starting the Application

#### Linux/macOS
```bash
# With full privileges (recommended)
sudo python3 nids.py

# Without sudo (requires capability setup)
python3 nids.py
```

#### Windows
```cmd
# Run Command Prompt as Administrator
# Navigate to the script directory
cd C:\path\to\nids\directory

# Run the application
python nids.py
```

### Using the Interface

#### 1. Initial Configuration (Settings Tab)
- **Select Network Interface**
  - Choose from dropdown menu
  - Click "Refresh Interfaces" if your interface isn't listed
  - Common interfaces:
    - Linux: `eth0`, `wlan0`, `enp0s3`
    - Windows: `Ethernet`, `Wi-Fi`
    - macOS: `en0`, `en1`
- **Configure Detection Options**
  - Enable/disable specific threat detection types
  - Set alert threshold (LOW/MEDIUM/HIGH/CRITICAL)
- **Save Settings**
  - Click "Save Settings" to persist configuration

#### 2. Start Monitoring (Dashboard Tab)
- Click **"Start Monitoring"** to begin packet capture
- View real-time statistics:
  - Total packets captured
  - Threats detected
  - Protocol distribution
  - System uptime
- Use **"Reset Statistics"** to clear counters

#### 3. Live Packet Monitoring (Live Monitor Tab)
- **Applying Filters**:
  - Protocol: Select from dropdown (All, TCP, UDP, ICMP, etc.)
  - Source IP: Enter specific IP address
  - Click "Apply Filter" to activate
  - Click "Clear Filter" to remove all filters
- **Auto-scroll Control**:
  - Toggle "Auto-scroll" button to enable/disable
  - When enabled, view automatically follows new packets
  - Manual scrolling temporarily pauses auto-scroll

#### 4. Security Alerts (Security Alerts Tab)
- **Alert Severity Levels**:
  - 🔴 CRITICAL (Red) - Immediate attention required
  - 🟠 HIGH (Orange) - Significant threat
  - 🟡 MEDIUM (Yellow) - Potential threat
  - 🔵 LOW (Blue) - Informational
- **Alert Management**:
  - "Clear Alerts" - Remove all alerts from display
  - "Export Alerts" - Save to JSON file with timestamp

#### 5. AI Analysis (AI Analysis Tab)
- **Setup**:
  1. Obtain API key from https://platform.openai.com
  2. Enter key in the text field
  3. Click "Set API Key"
  4. Verify status shows "Configured"
- **Generate Analysis**:
  - Click "Generate AI Summary"
  - Wait for AI to process threat data
  - Review comprehensive threat analysis

## Configuration Options

### Detection Settings
| Setting | Description | Default |
|---------|-------------|---------|
| Port Scan Detection | Identifies multiple port connection attempts from single source | Enabled |
| Flood Attack Detection | Detects SYN/ICMP flood attacks based on packet rate | Enabled |
| Malicious Payload Detection | Scans packet payloads for suspicious patterns | Enabled |

### Alert Threshold Levels
| Level | Description | Use Case |
|-------|-------------|----------|
| LOW | Shows all detected events | Development/Testing |
| MEDIUM | Filters minor events | Normal operations |
| HIGH | Only significant threats | Production environments |
| CRITICAL | Emergency threats only | High-security environments |

### Detection Thresholds (Advanced)
Modify in source code if needed:
```python
self.thresholds = {
    'port_scan_limit': 5,      # Ports before alert
    'syn_flood_limit': 100,    # SYN packets/minute
    'icmp_flood_limit': 50,    # ICMP packets/minute
    'reset_interval': 60       # Counter reset (seconds)
}
```

## Troubleshooting Guide

### Issue 1: Permission Denied Error
**Symptoms**: "Permission denied on interface" error message

**Solutions**:
```bash
# Linux/macOS
sudo python3 nids.py

# Alternative: Set capabilities
sudo setcap cap_net_raw=eip $(which python3)

# Windows: Run as Administrator
# Right-click → Run as Administrator
```

### Issue 2: No Interface Found
**Symptoms**: "Interface not found" or empty interface list

**Solutions**:
1. Verify available interfaces:
```bash
# Linux
ip addr show
ifconfig -a

# Windows
ipconfig /all

# macOS
ifconfig -a
networksetup -listallhardwareports
```

2. Refresh interface list in Settings tab
3. Manually enter interface name if not listed

### Issue 3: Import/Module Errors
**Symptoms**: "ModuleNotFoundError" messages

**Solutions**:
```bash
# Verify installations
pip list | grep -E "psutil|scapy|openai"

# Reinstall packages
pip uninstall psutil scapy openai
pip install --upgrade psutil scapy openai

# Check Python version
python --version  # Should be 3.7+
```

### Issue 4: Tkinter Not Available
**Symptoms**: "No module named 'tkinter'" error

**Solutions**:
```bash
# Linux
sudo apt-get install python3-tk

# macOS
brew install python-tk

# Windows
# Reinstall Python with tkinter option enabled
```

### Issue 5: No Packets Captured
**Symptoms**: Application runs but packet count remains zero

**Checklist**:
- ✓ Correct interface selected
- ✓ Interface is active and has IP address
- ✓ Network traffic is present
- ✓ Firewall not blocking packet capture
- ✓ Antivirus not interfering

**Test Network Activity**:
```bash
# Generate test traffic
ping google.com
curl http://example.com
```

### Issue 6: AI Analysis Failures
**Symptoms**: "AI analysis not available" or API errors

**Solutions**:
1. Verify API key is correct
2. Check OpenAI account status and credits
3. Ensure internet connectivity
4. Verify firewall allows HTTPS to api.openai.com

### Issue 7: High Memory Usage
**Symptoms**: Application consuming excessive RAM

**Solutions**:
1. Clear packet display regularly
2. Reduce packet buffer (modify in code):
```python
# In display_packet method
if len(children) > 200:  # Reduce from 500
```
3. Restart monitoring periodically
4. Apply filters to reduce packet processing

### Issue 8: Application Crashes
**Symptoms**: Unexpected application termination

**Debugging Steps**:
1. Run from terminal to see error messages
2. Check for conflicting software (VPN, firewall)
3. Verify system resources (RAM, CPU)
4. Test with different interfaces

## Performance Optimization

### Network Traffic Optimization
1. **Use Filters**: Reduce processing overhead
   - Filter by specific protocols
   - Filter by IP addresses
   - Focus on relevant traffic

2. **Adjust Thresholds**: Balance detection vs performance
   ```python
   # Increase limits to reduce false positives
   'port_scan_limit': 10,  # Was 5
   'syn_flood_limit': 200,  # Was 100
   ```

3. **Limit Packet Display**: Modify buffer size
   ```python
   # In display_packet method
   if len(children) > 100:  # Reduced buffer
   ```

### System Resource Management
- **CPU**: Use filters to reduce packet processing
- **Memory**: Clear alerts and packet display periodically
- **Disk I/O**: Limit JSON export frequency

## Security Considerations

### Legal and Ethical Guidelines
⚠️ **IMPORTANT**: Only monitor networks you own or have explicit permission to monitor

### Best Practices
1. **API Key Security**
   - Never commit API keys to version control
   - Use environment variables:
   ```python
   api_key = os.getenv('OPENAI_API_KEY')
   ```

2. **Data Protection**
   - Secure JSON export files (contain network data)
   - Encrypt sensitive exports
   - Delete old capture data regularly

3. **Access Control**
   - Restrict application access
   - Use strong system passwords
   - Enable firewall rules

4. **Updates and Patches**
   ```bash
   # Keep dependencies updated
   pip install --upgrade psutil scapy openai
   ```

## File Outputs

| File | Purpose | Location | Format |
|------|---------|----------|--------|
| `nids_settings.json` | Saved configuration | Script directory | JSON |
| `nids_alerts_YYYYMMDD_HHMMSS.json` | Alert exports | Script directory | JSON |
| Log files (if enabled) | Debug information | Script directory | Text |

### Export File Structure
```json
{
  "type": "Port Scan",
  "severity": "HIGH",
  "source": "192.168.1.100",
  "description": "Potential port scan detected",
  "timestamp": "2024-01-15 14:30:45"
}
```

## Known Limitations

### Technical Limitations
- Requires administrative privileges (no workaround for packet capture)
- IPv6 support is limited compared to IPv4
- Cannot decrypt encrypted traffic (HTTPS, VPN)
- Performance degrades on networks >1Gbps

### Feature Limitations
- AI analysis requires paid OpenAI API access
- Maximum 500 packets displayed in GUI
- No built-in packet replay functionality
- Limited to passive monitoring (no active response)

### Platform-Specific Issues
- **Windows**: May require Npcap reinstall after Windows updates
- **Linux**: Some distributions require additional configuration
- **macOS**: May need System Integrity Protection adjustments

## Quick Reference Card

### Common Commands
```bash
# Start monitoring
sudo python3 nids.py

# Check dependencies
pip list | grep -E "psutil|scapy|openai"

# Find network interfaces
ip addr show  # Linux
ipconfig /all  # Windows
ifconfig -a  # macOS

# Test permissions
python3 -c "from scapy.all import sniff; print('Permissions OK')"
```

### Keyboard Shortcuts
- `Ctrl+C`: Stop monitoring (in terminal)
- `Tab`: Navigate between GUI tabs
- `Space`: Toggle checkboxes
- `Enter`: Activate buttons

## Support Information

### Getting Help
When reporting issues, provide:
1. Operating system and version
2. Python version (`python --version`)
3. Complete error message
4. Network interface type
5. Steps to reproduce
6. Screenshot if GUI-related

### Version Information
- Application Version: 1.0.0
- Last Updated: 2024
- Python Requirement: 3.7+
- License: Educational Use

---

*This documentation is for the Network Intrusion Detection System (NIDS) student project. Ensure compliance with local laws regarding network monitoring.*
