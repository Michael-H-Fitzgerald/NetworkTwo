import socket
import struct
import threading
import time

class IPObj:
  def __init__(self, hostanme, ipaddr):
    self.hostanme = hostanme
    self.ipaddr = ipaddr
class checkObj:
  def __init__(self, Ipaddr, IPID,Port):
    self.Ipaddr = Ipaddr
    self.IPID = IPID
    self.Port = Port



def listOfIp():
    f = open('targets.txt')
    stuff = []
    for line in f:
        x = line.rstrip()
        y = socket.gethostbyname(x)
        z = IPObj(x,y)
        stuff.append(z)
    f.close()
    return stuff
arrayToCheck = [];
PortNum = 33434
l_IP = '192.168.1.6'
msg = "measurement for class project.questions to student mhf25@case.edu or professor mxr@case.edu"
def rec_Msg():
    while True:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.bind(("", 0))
        data,address = recv_sock.recvfrom(1500)
        hop_count = 32 - data[36]
        source_ipaddr = socket.inet_ntoa(data[12:16])
        dest_ipaddr = socket.inet_ntoa(data[16:20])
        source_hostname = socket.gethostbyaddr(dest_ipaddr)
        resp_source_ipaddr = socket.inet_ntoa(data[40:44])
        resp_dest_ipaddr = socket.inet_ntoa(data[44:48])
        timeStamp = int((round(time.time()) - round(data[32:34]),3) *1000)
        dest_port = struct.unpack("!H", data[50:52])[0]
        matchTypes = ""
        isInStuff = False;
        filledStuff = []
        # for x in arrayToCheck:
        #     if dest_ipaddr == x.ipaddr:
        #         filledStuff.append("IP address")
        #         isInStuff = True
        #     elif dest_port == x.Port:
        #         filledStuff.append("Port")
        #         isInStuff = True
        #     elif data[32:34] == x.IPID:
        #         filledStuff.append("IPID")
        #         isInStuff = True
        # if isInStuff == True:
        #     myMatch = ""
        #     for matches in filledStuff:
        MyMatch = ""
        source_hostname = source_hostname.decode("utf-8")
        source_ipaddr = source_ipaddr.decode("utf-8")
        print("Target:" + source_hostname + ";" + source_ipaddr + "Hops:" + hop_count + ";" + "RTT:" + timeStamp +";" + "Matched on:" + MyMatch)


def sendMsg():
    myTime = time.time()
    payload = bytes(msg + 'a'*(1472 - len(msg)), 'ascii')
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    myIpAdr = listOfIp()
    for x in myIpAdr:
        someTime = time.time()
        myTimeRound = int(round(someTime,3)*1000 - round(myTime,3) *1000)
        myIp = x.ipaddr
        myHostname = x.hostanme
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = myTimeRound  #IDTime
        ip_frag_off = 0
        ip_ttl = 32
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0  # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton(l_IP)  # Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton(myIp)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        # the ! in the pack format string means network order
        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
        ip_check, ip_saddr, ip_daddr)
        ip_header_you_previously_filled_out = ip_header
        sport = 4711  # arbitrary source port
        dport = PortNum  # arbitrary destination port
        length = len(payload)+8
        checksum = 0
        udp_header = struct.pack('!HHHH', sport, dport, length, checksum)
        udp_header_you_previously_filled_out = udp_header
        probe_packet = ip_header_you_previously_filled_out + udp_header_you_previously_filled_out + payload;
        myObject = checkObj(x.ipaddr,ip_id,PortNum)
        arrayToCheck.append(myObject)
        s.sendto(probe_packet, (x.ipaddr, PortNum))
    s.close()
def main():
    mySendThread = threading.Thread(target=sendMsg())
    myListenThread = threading.Thread(target=rec_Msg())
    myListenThread.start()
    mySendThread.start()
main()