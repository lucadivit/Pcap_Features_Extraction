from scapy.all import *
from FeaturesCalc import FeaturesCalc
from CSV import CSV
from PacketFilter import PacketFilter
from AttackerCalc import AttackerCalc
import glob

class CreateFeaturesHandler():

    def __init__(self, pkts_window_size=10, single_csv=True):
        self.pkts_window_size = pkts_window_size
        assert self.pkts_window_size >=1, "Invalid window size (it must be >=1)"
        self.single_csv = single_csv
        assert (self.single_csv is True) or (self.single_csv is False), "Invalid value for the single_csv option (it must be a boolean)"
        self.featuresCalc = FeaturesCalc(flow_type="malware", min_window_size=pkts_window_size)
        ip_to_ignore = ["127.0.0.1"]
        self.filter_1 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, TCP=True)
        self.filter_2 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, UDP=True)
        self.filter_3 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, ICMP=True)
        self.filters = [self.filter_1, self.filter_2, self.filter_3]

        if(self.single_csv):
            self.csv = CSV(file_name="features")
            self.csv.create_empty_csv()
            self.csv.add_row(self.featuresCalc.get_features_name())

    def compute_features(self):

        def malware_features():
            folder_name = "Pcaps_Malware"
            flow_type = "malware"
            if (self.featuresCalc.get_flow_type() == flow_type):
                pass
            else:
                self.featuresCalc.set_flow_type(flow_type)
            for pcap in glob.glob(folder_name + "/" + "*.pcap"):
                if(self.single_csv):
                    csv = self.csv
                else:
                    pcap_name = pcap.split("/")
                    pcap_name = pcap_name[len(pcap_name)-1].replace(".pcap", "")
                    csv = CSV(file_name=pcap_name, folder_name="Malware_Features")
                    csv.create_empty_csv()
                    csv.add_row(self.featuresCalc.get_features_name())
                array_of_pkts = []
                print("\nCalcolo features di " + pcap + "\n")
                attacker = AttackerCalc(pcap=pcap)
                ip_to_consider = attacker.compute_attacker()
                for filter in self.filters:
                    filter.set_ip_whitelist_filter(ip_to_consider)
                pkts = rdpcap(pcap)
                filter_res=[]
                for pkt in pkts:
                    for filter in self.filters:
                        if(filter.check_packet_filter(pkt)):
                            filter_res.append(True)
                        else:
                            filter_res.append(False)
                    if(True in filter_res):
                        array_of_pkts.append(pkt)
                    if (len(array_of_pkts) >= self.featuresCalc.get_min_window_size()):
                        features = self.featuresCalc.compute_features(array_of_pkts)
                        csv.add_row(features)
                        array_of_pkts.clear()
                    filter_res.clear()

        def legitimate_features():
            folder_name = "Pcaps_Legitimate"
            flow_type = "legitimate"
            if (self.featuresCalc.get_flow_type() == flow_type):
                pass
            else:
                self.featuresCalc.set_flow_type(flow_type)
            for filter in self.filters:
                filter.set_ip_whitelist_filter([])
            for pcap in glob.glob(folder_name + "/" + "*.pcap"):
                if(self.single_csv):
                    csv = self.csv
                else:
                    pcap_name = pcap.split("/")
                    pcap_name = pcap_name[len(pcap_name) - 1].replace(".pcap", "")
                    csv = CSV(file_name=pcap_name, folder_name="Legitimate_Features")
                    csv.create_empty_csv()
                    csv.add_row(self.featuresCalc.get_features_name())
                array_of_pkts = []
                filter_res = []
                print("\nComputing features for " + pcap + "\n")
                pkts = rdpcap(pcap)
                for pkt in pkts:
                    for filter in self.filters:
                        if(filter.check_packet_filter(pkt)):
                            filter_res.append(True)
                        else:
                            filter_res.append(False)
                    if(True in filter_res):
                        array_of_pkts.append(pkt)
                    if (len(array_of_pkts) >= self.featuresCalc.get_min_window_size()):
                        features = self.featuresCalc.compute_features(array_of_pkts)
                        csv.add_row(features)
                        array_of_pkts.clear()
                    filter_res.clear()

        malware_features()
        legitimate_features()
