from scapy.all import sniff, IP, TCP, ICMP

def show_packet(packet):
    if IP in packet :
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")

        print(f"Source: {src_ip} -->> Destination: {dst_ip} ) | Potocol: {proto_name}" )

        if TCP in packet:
            print(f"     TCF Port: {packet[TCP].sport} -->> {packet[TCP].dport}")
        
        elif UDP in packet:
            print(f"     UDP Port: {packet[UDP].sport} -->> {packet[UDP].dport}")

        elif icmp in packet:
            print("     ICMP Packet     ")

        if packet.haslayer("Raw"):
            print(f"   Payload length: {len(packet['Raw'].load)} bytes")


sniff(count= 10, prn=show_packet)