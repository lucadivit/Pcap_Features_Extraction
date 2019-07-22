# Pcap_Features_Extraction
This program allow you to extract some features from pcap files.
## Folders
You have to put some pcaps in respective folders.
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
- Avg_DNS_over_TCP: The average of ration DNS/TCP in a window of packets.
- Label: 0|1 respectively if pcap is legitimate or malware.
## CSV
The features are saved in a csv file.
### Example
```
csv = CSV(file_name="features")
csv.create_empty_csv()
#Here i add the header of csv file.
csv.add_row(featuresCalc.get_features_name())
#Here i add a generic row.
features = featuresCalc.compute_features(array_of_pkts)
csv.add_row(features)
```
## Attacker Calculation
AttackerCalc.py file computes an attacker from a malware pcap. The first ip in a malware pcap is probably the attacker because it starts the communication flow.

## Packet Filter 
PacketFilter.py file filters a packet. 
### Example
```
attacker = AttackerCalc(pcap=pcap)
ip_to_consider = attacker.compute_attacker()
ip_to_ignore = ["127.0.0.1"]

filter_1 = PacketFilter(ip_whitelist_filter=ip_to_consider, ip_blacklist_filter=[], TCP=True)
```
This filter accepts all the packets with ip: ip_to_consider which have TCP layer.
```
filter_2 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, UDP=True)
```
This filter accepts all the packets which haven't ip: ip_to_ignore with UDP layer.
```
filter_3 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=[], IPv4=True)
```
This filter accepts all packets with IP layer.
You can use these filters in the following way:
```
filter_1 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=[], TCP=True, UDP=False)
filter_2 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=[], TCP=False, UDP=True)
if ((filter_2.check_packet_filter(pkt) or filter_1.check_packet_filter(pkt)) is True):
    print("pkt accepted")
```
This code accepts a packet if it has a TCP Layer or UDP Layer.

## Example Of Usage
In Main.py file there is an example of usage of this program. You can run it with:
```
python3 Main.py
```
This file creates a single csv every run. So if you put 4 pcaps in a generic folder (or in both folders), the Main.py file creates a single csv with features of 4 (or 8) pcaps.
