from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_analyzer(packet):

    if packet.haslayer(IP):

        print("\n" + "="*50)

        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if packet.haslayer(TCP):
            print("Protocol: TCP")

        elif packet.haslayer(UDP):
            print("Protocol: UDP")

        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")

        if packet.haslayer(Raw):
            print("Payload:", packet[Raw].load[:100])

print("Starting Network Sniffer...")
sniff(prn=packet_analyzer, store=False)
