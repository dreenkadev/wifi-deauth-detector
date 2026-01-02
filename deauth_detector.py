#!/usr/bin/env python3
"""
WiFi Deauthentication Detector - Monitor and detect WiFi deauth attacks

Features:
- Monitor 802.11 deauth/disassoc frames
- Real-time alerting
- Attack source identification
- Target analysis
- Statistics and logging
- Multiple interface support
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


@dataclass
class DeauthEvent:
    timestamp: str
    source_mac: str
    dest_mac: str
    bssid: str
    frame_type: str  # deauth or disassoc
    reason_code: int
    channel: Optional[int] = None


@dataclass
class Alert:
    timestamp: str
    severity: str
    attack_type: str
    source_mac: str
    target_mac: str
    bssid: str
    frame_count: int
    description: str


# Deauth reason codes
REASON_CODES = {
    0: "Reserved",
    1: "Unspecified",
    2: "Previous auth no longer valid",
    3: "Station leaving",
    4: "Inactivity timeout",
    5: "AP overloaded",
    6: "Class 2 frame from non-auth station",
    7: "Class 3 frame from non-assoc station",
    8: "Station leaving (Disassoc)",
    9: "Not authenticated",
    10: "Power capability unacceptable",
    11: "Supported channels unacceptable",
}


class DeauthDetector:
    def __init__(self, interface: str, threshold: int = 10, window: int = 60):
        self.interface = interface
        self.threshold = threshold  # frames per window to trigger alert
        self.window = window        # time window in seconds
        
        self.events: List[DeauthEvent] = []
        self.alerts: List[Alert] = []
        self.running = False
        
        # Track deauth counts per source/target pair
        self.deauth_counts: Dict[str, List[float]] = defaultdict(list)
        self.source_counts = Counter()
        self.target_counts = Counter()
        
    def start_monitor(self):
        """Start monitoring for deauth frames"""
        self.running = True
        
        print(f"{Colors.CYAN}Starting WiFi deauth monitoring...{Colors.RESET}")
        print(f"Interface: {self.interface}")
        print(f"Threshold: {self.threshold} frames/{self.window}s")
        print(f"\n{Colors.YELLOW}Waiting for deauth frames... (Ctrl+C to stop){Colors.RESET}\n")
        
        try:
            # Use tcpdump to capture deauth frames
            # Filter for deauth (subtype 0xc) and disassoc (subtype 0xa) frames
            cmd = [
                'tcpdump', '-i', self.interface, '-l', '-e',
                'type mgt subtype deauth or type mgt subtype disassoc'
            ]
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self.running:
                line = proc.stdout.readline()
                if line:
                    self.parse_frame(line)
                    
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            
    def parse_frame(self, line: str):
        """Parse tcpdump output for deauth/disassoc frames"""
        try:
            # Extract MAC addresses from tcpdump output
            parts = line.split()
            
            # Simple extraction - format varies by tcpdump version
            frame_type = "deauth" if "Deauthentication" in line else "disassoc"
            
            # Find MAC addresses (format: xx:xx:xx:xx:xx:xx)
            macs = []
            for part in parts:
                if len(part) == 17 and part.count(':') == 5:
                    macs.append(part.lower())
            
            if len(macs) >= 2:
                event = DeauthEvent(
                    timestamp=datetime.now().isoformat(),
                    source_mac=macs[0],
                    dest_mac=macs[1],
                    bssid=macs[2] if len(macs) > 2 else macs[0],
                    frame_type=frame_type,
                    reason_code=0
                )
                
                self.process_event(event)
                
        except Exception:
            pass
    
    def process_event(self, event: DeauthEvent):
        """Process a deauth event and check for attacks"""
        self.events.append(event)
        
        # Update counters
        self.source_counts[event.source_mac] += 1
        self.target_counts[event.dest_mac] += 1
        
        # Track timing for threshold detection
        key = f"{event.source_mac}->{event.dest_mac}"
        current_time = time.time()
        self.deauth_counts[key].append(current_time)
        
        # Remove old entries
        self.deauth_counts[key] = [
            t for t in self.deauth_counts[key]
            if current_time - t < self.window
        ]
        
        # Print event
        self.print_event(event)
        
        # Check threshold
        if len(self.deauth_counts[key]) >= self.threshold:
            self.generate_alert(event, len(self.deauth_counts[key]))
            
    def print_event(self, event: DeauthEvent):
        """Print deauth event"""
        icon = "🔴" if event.frame_type == "deauth" else "🟡"
        
        print(f"{icon} {Colors.DIM}{event.timestamp[11:19]}{Colors.RESET} ", end="")
        print(f"{Colors.RED}{event.frame_type.upper():8}{Colors.RESET} ", end="")
        print(f"{event.source_mac} → {event.dest_mac}")
        
    def generate_alert(self, event: DeauthEvent, count: int):
        """Generate attack alert"""
        # Determine attack type
        if event.dest_mac == "ff:ff:ff:ff:ff:ff":
            attack_type = "Broadcast Deauth Attack"
            severity = "critical"
            description = f"Broadcast deauth flood from {event.source_mac}"
        else:
            attack_type = "Targeted Deauth Attack"
            severity = "high"
            description = f"Targeted deauth attack: {event.source_mac} → {event.dest_mac}"
        
        alert = Alert(
            timestamp=event.timestamp,
            severity=severity,
            attack_type=attack_type,
            source_mac=event.source_mac,
            target_mac=event.dest_mac,
            bssid=event.bssid,
            frame_count=count,
            description=description
        )
        
        self.alerts.append(alert)
        self.print_alert(alert)
        
    def print_alert(self, alert: Alert):
        """Print alert prominently"""
        color = Colors.RED if alert.severity == "critical" else Colors.YELLOW
        
        print(f"\n{color}{'═' * 60}")
        print(f"  ⚠️  ALERT: {alert.attack_type}")
        print(f"  Severity: {alert.severity.upper()}")
        print(f"  Source: {alert.source_mac}")
        print(f"  Target: {alert.target_mac}")
        print(f"  BSSID: {alert.bssid}")
        print(f"  Frames: {alert.frame_count} in {self.window}s")
        print(f"{'═' * 60}{Colors.RESET}\n")
        
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_events': len(self.events),
            'total_alerts': len(self.alerts),
            'unique_sources': len(self.source_counts),
            'unique_targets': len(self.target_counts),
            'top_sources': self.source_counts.most_common(5),
            'top_targets': self.target_counts.most_common(5)
        }


def demo_mode():
    """Run demonstration with sample events"""
    print(f"{Colors.CYAN}Running demo mode with simulated events...{Colors.RESET}\n")
    
    detector = DeauthDetector("demo", threshold=3, window=10)
    
    # Simulate deauth events
    events = [
        ("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", "deauth"),
        ("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", "deauth"),
        ("aa:bb:cc:dd:ee:02", "ff:ff:ff:ff:ff:ff", "deauth"),  # Broadcast
        ("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", "deauth"),  # Triggers alert
        ("aa:bb:cc:dd:ee:02", "ff:ff:ff:ff:ff:ff", "deauth"),
        ("aa:bb:cc:dd:ee:02", "ff:ff:ff:ff:ff:ff", "deauth"),  # Triggers alert
        ("aa:bb:cc:dd:ee:03", "77:88:99:aa:bb:cc", "disassoc"),
        ("aa:bb:cc:dd:ee:01", "11:22:33:44:55:66", "deauth"),
    ]
    
    for src, dst, ftype in events:
        event = DeauthEvent(
            timestamp=datetime.now().isoformat(),
            source_mac=src,
            dest_mac=dst,
            bssid=src,
            frame_type=ftype,
            reason_code=1
        )
        detector.process_event(event)
        time.sleep(0.5)
    
    # Print stats
    stats = detector.get_stats()
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Statistics:{Colors.RESET}")
    print(f"  Total events: {stats['total_events']}")
    print(f"  Alerts triggered: {stats['total_alerts']}")
    print(f"  Unique sources: {stats['unique_sources']}")
    print(f"  Unique targets: {stats['unique_targets']}")
    
    if stats['top_sources']:
        print(f"\n{Colors.BOLD}Top Attack Sources:{Colors.RESET}")
        for mac, count in stats['top_sources']:
            print(f"  {mac}: {count} frames")


def print_banner():
    print(f"""{Colors.CYAN}
 __        ___ _____ _   ____             _   _     
 \ \      / (_)  ___(_) |  _ \  ___  __ _| |_| |__  
  \ \ /\ / /| | |_  | | | | | |/ _ \/ _` | __| '_ \ 
   \ V  V / | |  _| | | | |_| |  __/ (_| | |_| | | |
    \_/\_/  |_|_|   |_| |____/ \___|\__,_|\__|_| |_|
{Colors.RESET}                                   v{VERSION}
""")


def main():
    parser = argparse.ArgumentParser(description="WiFi Deauth Detector")
    parser.add_argument("-i", "--interface", default="wlan0", help="Wireless interface")
    parser.add_argument("-t", "--threshold", type=int, default=10, help="Alert threshold")
    parser.add_argument("-w", "--window", type=int, default=60, help="Time window (seconds)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    # Check for root
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Warning: Root privileges recommended for packet capture")
        print(f"Use --demo for demonstration mode.{Colors.RESET}\n")
    
    detector = DeauthDetector(
        interface=args.interface,
        threshold=args.threshold,
        window=args.window
    )
    
    try:
        detector.start_monitor()
    except KeyboardInterrupt:
        pass
    
    if args.output:
        output = {
            'stats': detector.get_stats(),
            'alerts': [asdict(a) for a in detector.alerts],
            'events': [asdict(e) for e in detector.events[-100:]]
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
