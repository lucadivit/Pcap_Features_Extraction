from scapy.all import *

class AttackerCalc():
    def __init__(self, pcap=None, list_of_packets=None, policy='first_ip', window_size=15, filter_ip=['0.0.0.0', '127.0.0.1'], number_of_ip=1):
        self.pcap = pcap
        self.policy = policy
        self.window_size = window_size
        self.pcap_rd = None
        self.filter = filter_ip
        self.number_of_ip = number_of_ip
        self.list_of_packets = list_of_packets
        assert self.get_number_of_ip() == 1, "Multiple attackers are not supported (yet)"
        assert self.get_window_size() > 0, "Invalid window size (it must be >=1)"

    def compute_attacker(self):
        policy = self.get_policy()
        if(policy == "first_ip"):
            ip = self.first_ip_policy()
        elif(policy == "max_in_window"):
            ip = self.max_in_window_policy()
        else:
            print("Please select a policy.")
        return ip

    def first_ip_policy(self):
        assert self.list_of_packets is not None or self.pcap is not None, "No PCAP or packets list has been provided"
        print("\n" + "Processing attacker information" + "\n")
        if(self.get_list_of_packets() is not None):
            pkts = self.get_list_of_packets()
        elif(self.get_pcap() is not None):
            pkts = rdpcap(self.get_pcap())
        else:
            print("No PCAP or packets list has been provided.")
            return []
        ip_list = []
        for i in range(0, len(pkts) - 1):
            if (pkts[i].haslayer("IP")):
                if (pkts[i]["IP"].src in self.get_filter()):
                    pass
                else:
                    ip_list.append(pkts[i]["IP"].src)
                    break
            else:
                pass
        return ip_list

    def max_in_window_policy(self):
        assert self.list_of_packets is not None or self.pcap is not None, "No PCAP or packets list has been provided"
        print("\n" + "Processing attacker information" + "\n")
        if(self.get_list_of_packets() is not None):
            pkts = self.get_list_of_packets()
        elif(self.get_pcap() is not None):
            pkts = rdpcap(self.get_pcap())
        else:
            print("No PCAP or packets list has been provided.")
            return []
        ip_dict = {}
        if(len(pkts) >= self.get_window_size()):
            for pkt in pkts:
                if (pkt.haslayer("IP")):
                    if(pkt["IP"].src in self.get_filter()):
                        pass
                    else:
                        ip = pkt["IP"].src
                        older_value = ip_dict.get(ip)
                        if (older_value != None):
                            new_value = older_value + 1
                            ip_dict.update({ip: new_value})
                        else:
                            ip_dict.update({ip: 1})
                else:
                    pass
        else:
            print("Window size is too small")
            return []

        def find_max_between_IP(ip_dict):
            ip = []
            i = 0
            for key, value in ip_dict.items():
                if (value > i):
                    i = value
                    if(len(ip) > 0):
                        ip.pop()
                    ip.append(key)
                else:
                    pass
            return ip

        ip = find_max_between_IP(ip_dict)
        return ip

    def set_number_of_ip(self, number_of_ip):
        self.number_of_ip = number_of_ip

    def get_number_of_ip(self):
        return self.number_of_ip

    def set_filter(self, filter):
        self.filter = filter

    def get_filter(self):
        return self.filter

    def add_ip_to_filter(self, list_of_ip):
        assert isinstance(list_of_ip, list), "IPs must be added to the filter in the form of a list"
        for ip in list_of_ip:
            self.filter.append(ip)

    def set_pcap(self, pcap):
        self.pcap = pcap

    def get_pcap(self):
        return self.pcap

    def set_policy(self, policy):
        self.policy = policy

    def get_policy(self):
        return self.policy

    def set_window_size(self, size):
        self.window_size = size

    def get_window_size(self):
        return self.window_size

    def set_list_of_packets(self, list_of_packets):
        self.list_of_packets = list_of_packets

    def get_list_of_packets(self):
        return self.list_of_packets