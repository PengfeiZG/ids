#!/usr/bin/env python3
"""
NIDS Test Suite - Traffic Generator for Testing IDS
This script generates various types of network traffic to test IDS detection capabilities
WARNING: Only use on networks you own or have explicit permission to test!
"""

import sys
import time
import random
import socket
import threading
import argparse
from datetime import datetime

try:
    from scapy.all import *
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

class IDSTestSuite:
    """Test suite for Network IDS"""
    
    def __init__(self, target_ip, interface=None, verbose=True):
        """
        Initialize test suite
        
        Args:
            target_ip: Target IP address for tests
            interface: Network interface to use
            verbose: Enable verbose output
        """
        self.target_ip = target_ip
        self.interface = interface
        self.verbose = verbose
        self.test_results = []
        
        # Test configuration
        self.config = {
            'port_scan_ports': 50,
            'syn_flood_packets': 200,
            'packet_flood_count': 1500,
            'suspicious_ports': [23, 135, 445, 3389, 5900],
            'test_delay': 3  # Delay between tests
        }
        
        print(f"""
        ╔════════════════════════════════════════╗
        ║        NIDS Test Suite v1.0           ║
        ╚════════════════════════════════════════╝
        
        Target IP: {self.target_ip}
        Interface: {self.interface or 'auto'}
        
        WARNING: This tool generates attack-like traffic.
        Only use on networks you own or have permission to test!
        """)
    
    def log(self, message, level="INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[-]"
        }.get(level, "[*]")
        
        if self.verbose:
            print(f"{timestamp} {prefix} {message}")
    
    def test_connectivity(self):
        """Test basic connectivity to target"""
        self.log("Testing connectivity to target...", "INFO")
        
        try:
            # Send ICMP ping
            response = sr1(IP(dst=self.target_ip)/ICMP(), timeout=2, verbose=0)
            if response:
                self.log(f"Target {self.target_ip} is reachable", "SUCCESS")
                return True
            else:
                self.log(f"Target {self.target_ip} did not respond to ping", "WARNING")
                return False
        except Exception as e:
            self.log(f"Connectivity test failed: {e}", "ERROR")
            return False
    
    def test_port_scan(self):
        """Simulate port scanning behavior"""
        self.log("Starting port scan simulation...", "INFO")
        test_name = "Port Scan Detection"
        
        try:
            ports_scanned = 0
            start_port = random.randint(1, 1000)
            
            for port in range(start_port, start_port + self.config['port_scan_ports']):
                # Send SYN packet
                packet = IP(dst=self.target_ip)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=port,
                    flags="S"
                )
                send(packet, verbose=0, iface=self.interface)
                ports_scanned += 1
                
                # Small delay to simulate real scanning
                time.sleep(0.05)
                
                if ports_scanned % 10 == 0:
                    self.log(f"Scanned {ports_scanned} ports...", "INFO")
            
            self.log(f"Port scan complete: {ports_scanned} ports scanned", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': f"Scanned {ports_scanned} ports"
            })
            
        except Exception as e:
            self.log(f"Port scan test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_syn_flood(self):
        """Simulate SYN flood attack"""
        self.log("Starting SYN flood simulation...", "INFO")
        test_name = "SYN Flood Detection"
        
        try:
            packets_sent = 0
            target_port = 80  # Target web server port
            
            for _ in range(self.config['syn_flood_packets']):
                # Random source port for each packet
                sport = random.randint(1024, 65535)
                
                # Create SYN packet
                packet = IP(dst=self.target_ip)/TCP(
                    sport=sport,
                    dport=target_port,
                    flags="S",
                    seq=random.randint(1000, 9000)
                )
                
                send(packet, verbose=0, iface=self.interface)
                packets_sent += 1
                
                if packets_sent % 50 == 0:
                    self.log(f"Sent {packets_sent} SYN packets...", "INFO")
            
            self.log(f"SYN flood complete: {packets_sent} packets sent", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': f"Sent {packets_sent} SYN packets"
            })
            
        except Exception as e:
            self.log(f"SYN flood test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_suspicious_ports(self):
        """Test connections to suspicious ports"""
        self.log("Testing suspicious port connections...", "INFO")
        test_name = "Suspicious Port Detection"
        
        try:
            connections_made = 0
            port_names = {
                23: "Telnet",
                135: "RPC",
                445: "SMB",
                3389: "RDP",
                5900: "VNC"
            }
            
            for port in self.config['suspicious_ports']:
                self.log(f"Connecting to port {port} ({port_names.get(port, 'Unknown')})", "INFO")
                
                # Send SYN to suspicious port
                packet = IP(dst=self.target_ip)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=port,
                    flags="S"
                )
                send(packet, verbose=0, iface=self.interface)
                connections_made += 1
                
                # Wait between connections
                time.sleep(1)
            
            self.log(f"Suspicious port test complete: {connections_made} connections", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': f"Connected to {connections_made} suspicious ports"
            })
            
        except Exception as e:
            self.log(f"Suspicious port test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_high_packet_rate(self):
        """Generate high packet rate traffic"""
        self.log("Starting high packet rate test...", "INFO")
        test_name = "High Packet Rate Detection"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            # Send packets rapidly
            for _ in range(self.config['packet_flood_count']):
                # Mix of ICMP and UDP packets
                if random.choice([True, False]):
                    packet = IP(dst=self.target_ip)/ICMP()
                else:
                    packet = IP(dst=self.target_ip)/UDP(
                        sport=random.randint(1024, 65535),
                        dport=random.randint(1024, 65535)
                    )
                
                send(packet, verbose=0, iface=self.interface)
                packets_sent += 1
                
                if packets_sent % 200 == 0:
                    elapsed = time.time() - start_time
                    rate = packets_sent / elapsed if elapsed > 0 else 0
                    self.log(f"Sent {packets_sent} packets ({rate:.0f} pps)", "INFO")
            
            elapsed = time.time() - start_time
            rate = packets_sent / elapsed if elapsed > 0 else 0
            
            self.log(f"High packet rate test complete: {packets_sent} packets at {rate:.0f} pps", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': f"Sent {packets_sent} packets at {rate:.0f} pps"
            })
            
        except Exception as e:
            self.log(f"High packet rate test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_dns_anomaly(self):
        """Test DNS anomaly detection"""
        self.log("Starting DNS anomaly test...", "INFO")
        test_name = "DNS Anomaly Detection"
        
        try:
            # Generate oversized DNS queries
            for i in range(10):
                # Create large DNS query
                query_name = "test" * 100 + f"{i}.example.com"
                packet = IP(dst=self.target_ip)/UDP(dport=53)/DNS(
                    rd=1,
                    qd=DNSQR(qname=query_name)
                )
                send(packet, verbose=0, iface=self.interface)
            
            self.log("DNS anomaly test complete", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': "Sent 10 oversized DNS queries"
            })
            
        except Exception as e:
            self.log(f"DNS anomaly test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_http_attack(self):
        """Simulate HTTP attack patterns"""
        self.log("Starting HTTP attack simulation...", "INFO")
        test_name = "HTTP Attack Detection"
        
        try:
            # Generate suspicious HTTP traffic
            for i in range(10):
                # Large HTTP request
                payload = "A" * 5000  # Large payload
                packet = IP(dst=self.target_ip)/TCP(dport=80, flags="PA")/payload
                send(packet, verbose=0, iface=self.interface)
                
                # SQL injection attempt pattern
                sql_payload = "' OR '1'='1"
                packet = IP(dst=self.target_ip)/TCP(dport=80, flags="PA")/sql_payload
                send(packet, verbose=0, iface=self.interface)
            
            self.log("HTTP attack test complete", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': "Sent suspicious HTTP requests"
            })
            
        except Exception as e:
            self.log(f"HTTP attack test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_icmp_flood(self):
        """Test ICMP flood detection"""
        self.log("Starting ICMP flood test...", "INFO")
        test_name = "ICMP Flood Detection"
        
        try:
            packets_sent = 0
            
            for _ in range(200):
                packet = IP(dst=self.target_ip)/ICMP()
                send(packet, verbose=0, iface=self.interface)
                packets_sent += 1
            
            self.log(f"ICMP flood test complete: {packets_sent} packets sent", "SUCCESS")
            self.test_results.append({
                'test': test_name,
                'status': 'COMPLETED',
                'details': f"Sent {packets_sent} ICMP packets"
            })
            
        except Exception as e:
            self.log(f"ICMP flood test failed: {e}", "ERROR")
            self.test_results.append({
                'test': test_name,
                'status': 'FAILED',
                'details': str(e)
            })
    
    def run_all_tests(self, tests=None):
        """Run all or selected tests"""
        available_tests = {
            'connectivity': self.test_connectivity,
            'port_scan': self.test_port_scan,
            'syn_flood': self.test_syn_flood,
            'suspicious_ports': self.test_suspicious_ports,
            'packet_flood': self.test_high_packet_rate,
            'dns_anomaly': self.test_dns_anomaly,
            'http_attack': self.test_http_attack,
            'icmp_flood': self.test_icmp_flood
        }
        
        # If no specific tests requested, run all except connectivity
        if tests is None:
            tests = ['port_scan', 'syn_flood', 'suspicious_ports', 
                    'packet_flood', 'dns_anomaly', 'http_attack', 'icmp_flood']
        
        # Always test connectivity first
        if not self.test_connectivity():
            self.log("Target may be unreachable, but continuing tests...", "WARNING")
        
        self.log(f"\nStarting test suite with {len(tests)} tests", "INFO")
        self.log("="*50, "INFO")
        
        for test_name in tests:
            if test_name in available_tests:
                self.log(f"\nRunning test: {test_name}", "INFO")
                self.log("-"*30, "INFO")
                
                available_tests[test_name]()
                
                # Delay between tests
                if test_name != tests[-1]:
                    self.log(f"Waiting {self.config['test_delay']} seconds before next test...", "INFO")
                    time.sleep(self.config['test_delay'])
            else:
                self.log(f"Unknown test: {test_name}", "ERROR")
        
        self.print_results()
    
    def print_results(self):
        """Print test results summary"""
        print("\n" + "="*60)
        print(" "*20 + "TEST RESULTS SUMMARY")
        print("="*60)
        
        for result in self.test_results:
            status_symbol = "✓" if result['status'] == 'COMPLETED' else "✗"
            print(f"{status_symbol} {result['test']}: {result['status']}")
            print(f"  Details: {result['details']}")
            print("-"*40)
        
        completed = sum(1 for r in self.test_results if r['status'] == 'COMPLETED')
        total = len(self.test_results)
        
        print(f"\nTests Completed: {completed}/{total}")
        print("="*60)
        
        # Save results to file
        with open('test_results.txt', 'w') as f:
            f.write("NIDS Test Suite Results\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"Time: {datetime.now()}\n\n")
            
            for result in self.test_results:
                f.write(f"{result['test']}: {result['status']}\n")
                f.write(f"Details: {result['details']}\n\n")
        
        print("\nResults saved to: test_results.txt")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='NIDS Test Suite - Generate test traffic for IDS testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_nids.py 192.168.1.100                    # Run all tests
  python test_nids.py 192.168.1.100 --tests port_scan  # Run specific test
  python test_nids.py 192.168.1.100 --interface eth0   # Specify interface
  python test_nids.py 192.168.1.100 --quick            # Run quick tests only
        """
    )
    
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-t', '--tests', nargs='+', 
                       choices=['port_scan', 'syn_flood', 'suspicious_ports',
                               'packet_flood', 'dns_anomaly', 'http_attack', 'icmp_flood'],
                       help='Specific tests to run')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Run quick test suite (port_scan and suspicious_ports only)')
    parser.add_argument('-v', '--verbose', action='store_true', default=True,
                       help='Verbose output (default: True)')
    
    args = parser.parse_args()
    
    # Check for root/admin privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Please run with: sudo python test_nids.py <target>")
        sys.exit(1)
    
    # Warning message
    print("\n" + "!"*60)
    print("WARNING: This tool generates attack-like network traffic!")
    print("Only use on networks you own or have explicit permission to test!")
    print("!"*60)
    
    response = input("\nDo you have permission to test the target network? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting. Only test networks you have permission to test.")
        sys.exit(0)
    
    # Initialize test suite
    tester = IDSTestSuite(args.target, args.interface, args.verbose)
    
    # Determine which tests to run
    if args.quick:
        tests = ['port_scan', 'suspicious_ports']
    else:
        tests = args.tests
    
    # Run tests
    try:
        tester.run_all_tests(tests)
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user")
        tester.print_results()
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()