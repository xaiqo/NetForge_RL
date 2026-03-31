import base64
import random
from typing import List, Union

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    ARP,
    ICMP,
    DNS,
    DNSQR,
    Dot11,
    Dot11Deauth,
    Dot11Disas,
    RadioTap,
    fragment,
    Packet,
)
from scapy.utils import wrpcap


class PCAPSynthesizer:
    """Translates abstract RL actions (netforge_rl_v3) into modeled Scapy

    packets for offline IDS ML model training.

    CRITICAL SAFETY CONSTRAINT:
    All operations are strictly offline. Packets are generated purely in memory
    and written to a .pcap file. No active transmission (send, sendp, sockets) is used.
    """

    def __init__(self, default_filename: str = 'dataset.pcap'):
        self.default_filename = default_filename

    def append_to_pcap(
        self, packets: Union[Packet, List[Packet]], filename: str = None
    ) -> None:
        """Appends Scapy packet object(s) to a .pcap file.

        ML Feature extraction pipelines will read these files to parse
        out headers, metadata, and simulated behaviors matching the
        signatures.
        """
        target_file = filename if filename is not None else self.default_filename
        # scapy's wrpcap supports appending directly
        wrpcap(target_file, packets, append=True)

    # ==========================================
    # 1. Reconnaissance
    # ==========================================
    def craft_syn_scan(
        self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, dst_port: int
    ) -> Packet:
        """Models a TCP SYN scan (Half-open scan).

        IDS ML Features:
          - High frequency of small packets with ONLY the SYN flag set.
          - Directed across a range of ports in a short time window.
        """
        sport = random.randint(1024, 65535)
        # S flag = SYN
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=sport, dport=dst_port, flags='S', seq=random.randint(1000, 9000)
            )
        )
        return pkt

    def craft_udp_scan(
        self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, dst_port: int
    ) -> Packet:
        """Models a UDP port scan.

        IDS ML Features:
          - Small, empty UDP datagrams targeting various ports.
          - Expects an ICMP Port Unreachable if closed, or no response if open/filtered.
        """
        sport = random.randint(1024, 65535)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=dst_port)
        )
        return pkt

    # ==========================================
    # 2. ARP Layer
    # ==========================================
    def craft_arp_spoof(
        self, attacker_mac: str, target_ip: str, spoofed_ip: str
    ) -> Packet:
        """Models ARP Spoofing (Cache Poisoning) signature.

        IDS ML Features:
          - Unsolicited ARP Replies (is-at) without corresponding Requests.
          - ARP headers mapping a known gateway IP to a differing/unrecognized MAC address.
        """
        # op=2 signifies an ARP Reply (is-at)
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=attacker_mac) / ARP(
            op=2, pdst=target_ip, psrc=spoofed_ip, hwsrc=attacker_mac
        )
        return pkt

    # ==========================================
    # 3. 802.11 Layer
    # ==========================================
    def craft_deauthentication(
        self, target_mac: str, bssid: str, reason_code: int = 7
    ) -> Packet:
        """Models a Wi-Fi Deauthentication frame.

        IDS ML Features:
          - Flood of management frames (Type 0, Subtype 12).
          - Source MAC often spoofed to the AP BSSID or broadcast.
        """
        # reason 7 = Class 3 frame received from nonassociated STA
        pkt = (
            RadioTap()
            / Dot11(type=0, subtype=12, addr1=target_mac, addr2=bssid, addr3=bssid)
            / Dot11Deauth(reason=reason_code)
        )
        return pkt

    def craft_disassociation(
        self, target_mac: str, bssid: str, reason_code: int = 8
    ) -> Packet:
        """Models a Wi-Fi Disassociation frame.

        IDS ML Features:
          - Management frames (Type 0, Subtype 10).
          - Unusually high volume forces devices off the network.
        """
        # reason 8 = Disassociated because sending STA is leaving
        pkt = (
            RadioTap()
            / Dot11(type=0, subtype=10, addr1=target_mac, addr2=bssid, addr3=bssid)
            / Dot11Disas(reason=reason_code)
        )
        return pkt

    # ==========================================
    # 4. IP Fragmentation
    # ==========================================
    def craft_ip_fragmentation(
        self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, payload: bytes
    ) -> List[Packet]:
        """Models NIDS Evasion via IP Fragmentation.

        IDS ML Features:
          - Small IP headers with the More Fragments (MF) flag set.
          - Overlapping fragment offsets.
          - Evasion: breaks known signatures across multiple packets.
        """
        ip_layer = IP(src=src_ip, dst=dst_ip)
        udp_layer = UDP(sport=12345, dport=80)
        full_packet = ip_layer / udp_layer / payload

        # scapy's built-in fragment generator cuts IP layer up based on fragsize
        fragments = fragment(full_packet, fragsize=8)

        # We must wrap each IP fragment in an Ethernet frame for the pcap
        eth_fragments = [Ether(src=src_mac, dst=dst_mac) / frag for frag in fragments]
        return eth_fragments

    # ==========================================
    # 5. Covert Tunneling
    # ==========================================
    def craft_dns_tunnel(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        exfil_domain: str,
        secret_data: str,
    ) -> Packet:
        """Models Data Exfiltration via DNS tunneling.

        IDS ML Features:
          - High Shannon entropy in DNS subdomains.
          - Unusually lengthy QNAMEs in DNS Queries containing Base64 encoded blobs.
        """
        # Base64 encode the dummy secret string
        encoded_payload = base64.b64encode(secret_data.encode()).decode('utf-8')
        # Remove padding for better stealth emulation, append base domain
        encoded_payload = encoded_payload.rstrip('=')
        query_name = f'{encoded_payload}.{exfil_domain}'

        # rd=1 (Recursion Desired), DNSQR encodes the query
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query_name))
        )
        return pkt

    def craft_icmp_tunnel(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        hidden_payload: bytes,
    ) -> Packet:
        """Models Covert C2 or Data Exfil via ICMP payload.

        IDS ML Features:
          - Standard pings typically have small, predictable payloads (e.g., repeating chars).
          - Tunneling creates abnormally large ICMP Echo Requests (Type=8) with encrypted/high-entropy data.
        """
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8)
            / hidden_payload
        )
        return pkt

    # ==========================================
    # 6. TCP Anomalies
    # ==========================================
    def craft_incomplete_tcp_handshake(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        seq_num: int,
    ) -> List[Packet]:
        """Models incomplete TCP handshakes (e.g., SYN-ACK received, but no ACK

        sent).

        IDS ML Features:
          - Asymmetric traffic flows.
          - State table exhaustion attempts (SYN Floods).
        """
        sport = random.randint(1024, 65535)

        # 1. Attacker sends SYN
        syn_pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dst_port, flags='S', seq=seq_num)
        )

        # 2. Server responds with SYN-ACK
        syn_ack_pkt = (
            Ether(src=dst_mac, dst=src_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(
                sport=dst_port,
                dport=sport,
                flags='SA',
                seq=random.randint(1000, 9000),
                ack=seq_num + 1,
            )
        )

        # (The final ACK is never sent by the attacker)
        return [syn_pkt, syn_ack_pkt]

    def craft_tcp_rst(
        self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, dst_port: int
    ) -> Packet:
        """Models anomalous TCP RST (Reset) packets.

        IDS ML Features:
          - Used heavily in session hijacking, port scanning teardowns, or aggressive evasions.
          - High volume of RST flags observed in normal flows indicates interference.
        """
        sport = random.randint(1024, 65535)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=sport, dport=dst_port, flags='R', seq=random.randint(1000, 9000)
            )
        )
        return pkt

    # ==========================================
    # 7. Green Team (Benign Traffic)
    # ==========================================
    def craft_benign_http_traffic(
        self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str
    ) -> List[Packet]:
        """Models normal web browsing traffic (TCP Handshake -> HTTP GET -> ACK

        -> Teardown).

        This establishes a baseline of benign flow duration, byte
        counts, and packet rates.
        """
        sport = random.randint(1024, 65535)
        seq_num = random.randint(1000, 9000)
        ack_num = random.randint(1000, 9000)

        # 3-way handshake
        syn = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=80, flags='S', seq=seq_num)
        )
        syn_ack = (
            Ether(src=dst_mac, dst=src_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(sport=80, dport=sport, flags='SA', seq=ack_num, ack=seq_num + 1)
        )
        ack = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=80, flags='A', seq=seq_num + 1, ack=ack_num + 1)
        )

        # HTTP GET Request
        payload = b'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
        push_ack = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=80, flags='PA', seq=seq_num + 1, ack=ack_num + 1)
            / payload
        )

        # Simple response and FIN teardown could follow, but we can simulate the flow start and payload
        return [syn, syn_ack, ack, push_ack]

    def craft_benign_dns_queries(
        self,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        domain: str = 'www.google.com',
    ) -> Packet:
        """Models standard, expected DNS resolution traffic.

        Provides a baseline for normal query length, TTLs, and entropy.
        """
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        return pkt

    def craft_benign_arp_broadcasts(
        self, src_mac: str, src_ip: str, target_ip: str
    ) -> Packet:
        """Models standard who-has ARP broadcast behavior.

        Normal baseline compared to unsolicited is-at ARP spoofing
        frames.
        """
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac) / ARP(
            op=1, pdst=target_ip, psrc=src_ip, hwsrc=src_mac
        )
        return pkt

    # ==========================================
    # 8. Blue Team (Defensive Footprints)
    # ==========================================
    def craft_icmp_host_unreachable(
        self,
        router_mac: str,
        attacker_mac: str,
        router_ip: str,
        attacker_ip: str,
        original_packet: Packet = None,
    ) -> Packet:
        """Models a network defense (e.g., IsolateHost) response dropping an

        attacker's packet.

        ICMP Type 3, Code 1 (Host Unreachable).
        """
        # Note: The original packet's IP header and top 8 bytes of payload are typically included in ICMP unreachable
        pkt = (
            Ether(src=router_mac, dst=attacker_mac)
            / IP(src=router_ip, dst=attacker_ip)
            / ICMP(type=3, code=1)
        )

        if original_packet and original_packet.haslayer(IP):
            # Attach a slice of the dropped packet as per RFC 792
            pkt = pkt / original_packet[IP]

        return pkt

    def craft_firewall_tcp_rst(
        self,
        fw_mac: str,
        attacker_mac: str,
        fw_ip: str,
        attacker_ip: str,
        attacker_port: int,
        target_port: int,
    ) -> Packet:
        """Models an active defense (e.g., BlockPort) where a firewall

        proactively sends a RST to terminate a malicious connection.
        """
        pkt = (
            Ether(src=fw_mac, dst=attacker_mac)
            / IP(src=fw_ip, dst=attacker_ip)
            / TCP(
                sport=target_port,
                dport=attacker_port,
                flags='R',
                seq=random.randint(1000, 9000),
            )
        )
        return pkt
