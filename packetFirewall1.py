from scapy.all import *

class Packet:
    def __init__(self, source_ip, destination_ip, protocol, payload):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.payload = payload

class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def allow_packet(self, packet):
        for rule in self.rules:
            if rule.matches(packet):
                return True
        return False

class Rule:
    def __init__(self, source_ip=None, destination_ip=None, protocol=None):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol

    def matches(self, packet):
        if self.source_ip and packet.source_ip != self.source_ip:
            return False
        if self.destination_ip and packet.destination_ip != self.destination_ip:
            return False
        if self.protocol and packet.protocol != self.protocol:
            return False
        return True

# Initialize the firewall
firewall = Firewall()

# Add rules to the firewall
rule1 = Rule(source_ip="192.168.1.1", protocol="TCP")
rule2 = Rule(destination_ip="10.0.0.1", protocol="UDP")
firewall.add_rule(rule1)
firewall.add_rule(rule2)

# Define a packet processing function
def process_packet(pkt):
    if IP in pkt:
        source_ip = pkt[IP].src
        destination_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        payload = str(pkt[IP].payload)
        
        packet = Packet(source_ip, destination_ip, protocol, payload)
        
        if firewall.allow_packet(packet):
            print("Allowed packet:", pkt.summary())
        else:
            print("Blocked packet:", pkt.summary())

# Start sniffing packets and applying firewall rules
try:
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    print("Exiting...")
