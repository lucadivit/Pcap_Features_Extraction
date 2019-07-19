from scapy.all import *
from FeaturesCalc import FeaturesCalc
from CSV import CSV
from PacketFilter import PacketFilter
from AttackerCalc import AttackerCalc
import glob

def main():

    pkts_window_size = 10
    ip_to_ignore = ["127.0.0.1"]
    featuresCalc = FeaturesCalc(flow_type="malware", min_window_size=pkts_window_size)
    filter_1 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, IPv4=True, TCP=True,
                            UDP=False)
    filter_2 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, IPv4=True, TCP=False,
                            UDP=True)
    filter_3 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, IPv4=True, TCP=False,
                            UDP=False)
    csv = CSV(file_name="features")
    csv.create_empty_csv()
    csv.add_row(featuresCalc.get_features_name())

    def malware_features():
        folder_name = "Pcaps_Malware"
        flow_type = "malware"
        if (featuresCalc.get_flow_type() == flow_type):
            pass
        else:
            featuresCalc.set_flow_type(flow_type)
        for pcap in glob.glob(folder_name + "/" + "*.pcap"):
            array_of_pkts = []
            attacker = AttackerCalc(pcap=pcap)
            ip_to_consider = attacker.compute_attacker()
            filter_1.set_ip_whitelist_filter(ip_to_consider)
            filter_2.set_ip_whitelist_filter(ip_to_consider)
            filter_3.set_ip_whitelist_filter(ip_to_consider)
            pkts = rdpcap(pcap)
            for pkt in pkts:
                if ((filter_2.check_packet_filter(pkt) or filter_1.check_packet_filter(pkt) or filter_3.check_packet_filter(pkt)) is True):
                    array_of_pkts.append(pkt)
                if (len(array_of_pkts) >= featuresCalc.get_min_window_size()):
                    features = featuresCalc.compute_features(array_of_pkts)
                    csv.add_row(features)
                    array_of_pkts.clear()

    def legitimate_features():
        folder_name = "Pcaps_Legitimate"
        flow_type = "legitimate"
        if (featuresCalc.get_flow_type() == flow_type):
            pass
        else:
            featuresCalc.set_flow_type(flow_type)
        filter_1.set_ip_whitelist_filter([])
        filter_2.set_ip_whitelist_filter([])
        filter_3.set_ip_whitelist_filter([])
        for pcap in glob.glob(folder_name + "/" + "*.pcap"):
            array_of_pkts = []
            pkts = rdpcap(pcap)
            for pkt in pkts:
                if ((filter_2.check_packet_filter(pkt) or filter_1.check_packet_filter(pkt) or filter_3.check_packet_filter(pkt)) is True):
                    array_of_pkts.append(pkt)
                if (len(array_of_pkts) >= featuresCalc.get_min_window_size()):
                    features = featuresCalc.compute_features(array_of_pkts)
                    csv.add_row(features)
                    array_of_pkts.clear()

    malware_features()
    legitimate_features()

if __name__== "__main__":
    main()