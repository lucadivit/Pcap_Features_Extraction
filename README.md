# Pcap_Features_Extraction
This program allow you to extract some features from pcap files.
## Features Calculation
FeaturesCalc.py file contains the code to calculate the features. This program is thinked for two type of pcaps: Malware Pcaps and Legitimate Pcaps. There are 26 features:
- Avg_syn_flag: The average of packets with syn flag active in a window of packtes.
- Avg_urg_flag
- Avg_fin_flag
- Avg_ack_flag
- Avg_psh_flag
- Avg_rst_flag
- Avg_DNS_pkt: The average pf DNS packets in a window of packets.
- Avg_TCP_pkt
- Avg_UDP_pkt
- Avg_ICMP_pkt
- Duration_window_flow: The time from the first packet to last packet in a window of packets.
- Avg_delta_time: The average of delta times in a window of packets. Delta time is the time from a packet to the next packet.
- Min_delta_time: The minimum delta time in a window of packets. 
- Max_delta_time: The maximum delta time in a window of packets. 
- StDev_delta_time: The Standard Deviation of delta time in a window of packets.
- Avg_pkts_lenght: The average of packet leghts in a window of packet.
- Min_pkts_lenght
- Max_pkts_lenght
- StDev_pkts_lenght
- Avg_small_payload_pkt: The average of packet with a small payload. A payload is considered small if his size is lower than 32 Byte.
- Avg_payload: The average of payload size in a window of packets.
- Min_payload
- Max_payload
- StDev_payload
- Avg_DNS_over_TCP
## Example Of Usage
In Main.py file there is an example of usage of this program. In my example i split pcap in two fields: Malware Pcap and Legitimate Pcap.
