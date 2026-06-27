from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        print("\n-------------------------------")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        else:
            print("Protocol       : Other")

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            print("Payload Preview:", payload[:50])

print("Starting Network Sniffer...")
print("Capturing 10 packets...\n")

sniff(prn=process_packet, count=10)

print("\nPacket capture completed.")
