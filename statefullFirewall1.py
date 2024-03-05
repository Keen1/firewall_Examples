class Packet:
    def __init__(self, source_ip, destination_ip, protocol):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol

class StatefulFirewall:
    def __init__(self):
        self.state_table = {}

    def allow_packet(self, packet):
        if self.is_packet_allowed(packet):
            self.update_state_table(packet)
            return True
        else:
            return False

    def is_packet_allowed(self, packet):
        # Check if packet belongs to an existing connection in the state table
        connection_key = (packet.source_ip, packet.destination_ip)
        if connection_key in self.state_table:
            return True
        else:
            return False

    def update_state_table(self, packet):
        # Update state table with the new connection or connection status
        connection_key = (packet.source_ip, packet.destination_ip)
        self.state_table[connection_key] = True

# Initialize the firewall
firewall = StatefulFirewall()

# Define a function to process incoming packets
def process_packet(packet):
    if firewall.allow_packet(packet):
        print("Allowed packet:", packet.source_ip, "->", packet.destination_ip)
    else:
        print("Blocked packet:", packet.source_ip, "->", packet.destination_ip)

# Simulate incoming packets
packets = [
    Packet("192.168.1.2", "8.8.8.8", "TCP"),
    Packet("8.8.8.8", "192.168.1.2", "TCP"),
    Packet("192.168.1.3", "10.0.0.1", "UDP")
]

# Start processing packets in a loop
for packet in packets:
    process_packet(packet)
