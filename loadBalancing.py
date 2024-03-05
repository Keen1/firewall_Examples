import random

class Packet:
    def __init__(self, source_ip, destination_ip, destination_port, payload):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.payload = payload

class LoadBalancer:
    def __init__(self, servers):
        self.servers = servers

    def choose_server(self):
        return random.choice(self.servers)

class Firewall:
    def __init__(self, load_balancer):
        self.load_balancer = load_balancer

    def dnat_packet(self, packet):
        # Choose a backend server for load balancing
        backend_server = self.load_balancer.choose_server()
        print(f"Forwarding packet to backend server: {backend_server}")

        # Modify packet destination IP and port
        packet.destination_ip = backend_server['ip']
        packet.destination_port = backend_server['port']

        return packet

# Initialize backend servers
backend_servers = [
    {'ip': '192.168.1.10', 'port': 80},
    {'ip': '192.168.1.11', 'port': 80},
    {'ip': '192.168.1.12', 'port': 80}
]

# Initialize load balancer
load_balancer = LoadBalancer(backend_servers)

# Initialize firewall
firewall = Firewall(load_balancer)

# Simulate incoming packets
incoming_packets = [
    Packet("192.168.1.2", "10.0.0.1", 8080, "HTTP request"),
    Packet("192.168.1.3", "10.0.0.1", 8080, "HTTP request"),
    Packet("192.168.1.4", "10.0.0.1", 8080, "HTTP request")
]

# Process incoming packets and perform DNAT load balancing
for packet in incoming_packets:
    processed_packet = firewall.dnat_packet(packet)
    print(f"Processed packet: Source IP: {processed_packet.source_ip}, Destination IP: {processed_packet.destination_ip}, Destination Port: {processed_packet.destination_port}")
