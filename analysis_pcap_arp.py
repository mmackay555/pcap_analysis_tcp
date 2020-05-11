import dpkt
def analysis_pcap_arp(filename):
    f = open(filename , 'rb')
    pcapfile = dpkt.pcap.Reader(f)
    current_pkt = [-1, -1, -1, -1, -1, -1, -1]
    arp_counter = 0
    found_pkt_flag = False
    request_pkt = []
    response_pkt = []
    for buf in pcapfile:
        byte_arr = bytearray(buf[1]);
        if(byte_arr[12].__eq__(0x08) and byte_arr[13].__eq__(0x06)):
            arp_counter = arp_counter + 1
            if(byte_arr[0].__eq__(current_pkt[6]) and not found_pkt_flag):
                if(byte_arr[1].__eq__(current_pkt[7])):
                    if (byte_arr[2].__eq__(current_pkt[8])):
                        if (byte_arr[3].__eq__(current_pkt[9])):
                            if (byte_arr[4].__eq__(current_pkt[10])):
                                if (byte_arr[5].__eq__(current_pkt[11])):
                                    request_pkt = current_pkt
                                    response_pkt = byte_arr
        current_pkt = byte_arr


    print("Total number of ARP packets:", arp_counter)
    print()
    print("Request Packet:")
    print("Hardware Type:", (request_pkt[14] << 2) + request_pkt[15])
    print("Protocol Type: 0x", "".join("{:02x}".format(request_pkt[16])), ''.join("{:02x}".format(request_pkt[17])), sep="")
    print("Hardware Size:", request_pkt[18])
    print("Protocol Size:", request_pkt[19])
    print("Opcode:", (request_pkt[20] << 2) + request_pkt[21])
    print("Sender MAC Address: ", "".join("{:02x}".format(request_pkt[22])), ":", "".join("{:02x}".format(request_pkt[23])),
          ":", "".join("{:02x}".format(request_pkt[24])), ":", "".join("{:02x}".format(request_pkt[25])), ":",
          "".join("{:02x}".format(request_pkt[26])), ":", "".join("{:02x}".format(request_pkt[27])), sep="")
    print("Sender IP Address: ", request_pkt[28], ".", request_pkt[29], ".", request_pkt[30], ".", request_pkt[31], sep="")
    print("Target MAC Address: ", "".join("{:02x}".format(request_pkt[32])), ":", "".join("{:02x}".format(request_pkt[33])),
          ":", "".join("{:02x}".format(request_pkt[34])), ":", "".join("{:02x}".format(request_pkt[35])), ":",
          "".join("{:02x}".format(request_pkt[36])), ":", "".join("{:02x}".format(request_pkt[37])), sep="")
    print("Target IP Address: ", request_pkt[38], ".", request_pkt[39], ".", request_pkt[40], ".", request_pkt[41], sep="")
    print()
    print("Response Packet:")
    print("Hardware Type:", (response_pkt[14] << 2) + response_pkt[15])
    print("Protocol Type: 0x", "".join("{:02x}".format(response_pkt[16])), ''.join("{:02x}".format(response_pkt[17])),
          sep="")
    print("Hardware Size:", response_pkt[18])
    print("Protocol Size:", response_pkt[19])
    print("Opcode:", (response_pkt[20] << 2) + response_pkt[21])
    print("Sender MAC Address: ", "".join("{:02x}".format(response_pkt[22])), ":",
          "".join("{:02x}".format(response_pkt[23])),
          ":", "".join("{:02x}".format(response_pkt[24])), ":", "".join("{:02x}".format(response_pkt[25])), ":",
          "".join("{:02x}".format(response_pkt[26])), ":", "".join("{:02x}".format(response_pkt[27])), sep="")
    print("Sender IP Address: ", response_pkt[28], ".", response_pkt[29], ".", response_pkt[30], ".", response_pkt[31],
          sep="")
    print("Target MAC Address: ", "".join("{:02x}".format(response_pkt[32])), ":",
          "".join("{:02x}".format(response_pkt[33])),
          ":", "".join("{:02x}".format(response_pkt[34])), ":", "".join("{:02x}".format(response_pkt[35])), ":",
          "".join("{:02x}".format(response_pkt[36])), ":", "".join("{:02x}".format(response_pkt[37])), sep="")
    print("Target IP Address: ", response_pkt[38], ".", response_pkt[39], ".", response_pkt[40], ".", response_pkt[41],
          sep="")
if __name__ == '__main__':
    file_str = input("Insert PCAP File Name: ")
    analysis_pcap_arp(file_str)
