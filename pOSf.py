from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import queue

class PassiveOSFingerprinter:
    def __init__(self):
        self.fingerprints = defaultdict(lambda: {
            'ttl': set(),
            'window_sizes': set(),
            'mss': set(),
            'timestamps': False,
            'window_scaling': False,
            'sack_permitted': False,
            'packet_count': 0,
            'last_seen': None
        })
        
        self.os_signatures = {
            'Windows': {
                'ttl': [128],
                'window_sizes': [8192, 16384, 65535],
                'typical_mss': [1460],
                'timestamps': True,
                'window_scaling': True
            },
            'Linux': {
                'ttl': [64],
                'window_sizes': [5840, 14600, 29200],
                'typical_mss': [1460],
                'timestamps': True,
                'window_scaling': True
            }
        }
        self.packet_queue = queue.Queue()
        self.is_running = True

    def analyze_packet(self, packet):
        if not (IP in packet and TCP in packet):
            return

        ip_src = packet[IP].src

        self.fingerprints[ip_src]['ttl'].add(packet[IP].ttl)
        self.fingerprints[ip_src]['packet_count'] += 1
        self.fingerprints[ip_src]['last_seen'] = time.time()

        if TCP in packet:
            self.fingerprints[ip_src]['window_sizes'].add(packet[TCP].window)
            
            if packet[TCP].options:
                for option_name, option_value in packet[TCP].options:
                    if option_name == 'MSS':
                        self.fingerprints[ip_src]['mss'].add(option_value)
                    elif option_name == 'Timestamp':
                        self.fingerprints[ip_src]['timestamps'] = True
                    elif option_name == 'WScale':
                        self.fingerprints[ip_src]['window_scaling'] = True
                    elif option_name == 'SAckOK':
                        self.fingerprints[ip_src]['sack_permitted'] = True

        # Add packet info to queue for real-time updates
        self.packet_queue.put(ip_src)

    def identify_os(self, ip):
        if ip not in self.fingerprints:
            return "Unknown"

        fp = self.fingerprints[ip]
        matches = defaultdict(int)

        for os_name, signature in self.os_signatures.items():
            if any(ttl in range(t - 5, t + 5) for t in signature['ttl'] for ttl in fp['ttl']):
                matches[os_name] += 1
            if any(ws in signature['window_sizes'] for ws in fp['window_sizes']):
                matches[os_name] += 1
            if any(mss in signature['typical_mss'] for mss in fp['mss']):
                matches[os_name] += 1
            if fp['timestamps'] == signature['timestamps']:
                matches[os_name] += 1
            if fp['window_scaling'] == signature['window_scaling']:
                matches[os_name] += 1

        if not matches:
            return "Unknown"

        return max(matches.items(), key=lambda x: x[1])[0]

    def start_sniffing(self, interface=None):
        print(f"Starting packet capture on interface: {interface or 'default'}")
        sniff(iface=interface, prn=self.analyze_packet, store=0)

    def get_results(self):
        results = {}
        for ip, fp in self.fingerprints.items():
            results[ip] = {
                'os': self.identify_os(ip),
                'fingerprint': {
                    'ttl': list(fp['ttl']),
                    'window_sizes': list(fp['window_sizes']),
                    'mss': list(fp['mss']),
                    'timestamps': fp['timestamps'],
                    'window_scaling': fp['window_scaling'],
                    'sack_permitted': fp['sack_permitted'],
                    'packet_count': fp['packet_count'],
                    'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', 
                                             time.localtime(fp['last_seen'])) if fp['last_seen'] else None
                }
            }
        return results