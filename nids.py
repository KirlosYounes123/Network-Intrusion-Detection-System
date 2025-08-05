import re
from scapy.all import *
import pathlib
import gzip
import math
import time
import scapy.plist
from io import StringIO
from io import BytesIO
import reassembler
from scapy.layers.inet import TCP, UDP, IP, Ether, ICMP, defragment
from scapy.layers.dns import DNS
from scapy.arch.windows import get_windows_if_list
conf.max_list_count = 1000
import subprocess
import json
import datetime


def Check_Bad_Checksums(Packet):
    if not Packet.haslayer(TCP):
        return True
    OriginalChecksum = Packet[TCP].chksum
    del Packet[TCP].chksum
    packet = IP(bytes(Packet[IP]))
    CalculatedChecksum = packet[TCP].chksum
    return OriginalChecksum == CalculatedChecksum

def Remove_Bad_Checksums(Packets):
    NonFalsePackets = []
    for eachpacket in Packets:
        if Check_Bad_Checksums(eachpacket):
            NonFalsePackets.append(eachpacket)
    return scapy.plist.PacketList(NonFalsePackets)

def Removing_Tcp_Duplicates(Packets):
    emptydict = {}
    for eachpacket in Packets:
        if eachpacket.haslayer(TCP):
            Syq = eachpacket[TCP].seq
            emptydict[Syq] = eachpacket
        else:
            emptydict[len(emptydict)] = eachpacket  
    return scapy.plist.PacketList(emptydict.values())

def Sorted_Tcp_Packets(Packets):
    def Temporary_Func(Srt):
        if Srt.haslayer(TCP):
            return Srt[TCP].seq
        return 0
    return scapy.plist.PacketList(sorted(Packets, key=Temporary_Func))

def Sniff_For_Seconds(Interface,Seconds,SaveName,SaveDir):
    ForFile = []
    ForPcapSave = []
    StartTime = time.time()
    MyiP = None
    TempInter = get_windows_if_list()[:7]
    for iface in TempInter:
        value = list(iface.values())
        try:
            if value[0] == Interface:
                MyiP = value[-2][1]
        except:
            pass
    def Stopper(Packet):
        return (time.time() - StartTime) > Seconds
    def Filterer(Packet):
        if IP in Packet and (TCP in Packet or UDP in Packet):
            ForPcapSave.append(Packet)
            return Packet
    def Processor(Packet):
        if Packet[IP].src == MyiP:
            Data = f"Iam Sending A Packet From {Packet[IP].src} → {Packet[IP].dst} From Source Port:{Packet[IP].sport} → Destination Port:{Packet[IP].dport}"
        elif Packet[IP].dst == MyiP:
            Data = f"I Got A Packet From {Packet[IP].src} From Source Port:{Packet[IP].sport} → Destination Port:{Packet[IP].dport}"
        else:
            Data = f"Other traffic: {Packet[IP].src} → {Packet[IP].dst}"
        print(Data)
        if SaveName != None:
            ForFile.append(Data)
    sniff(iface="{}".format(Interface),store = 0, prn=Processor, lfilter=Filterer, stop_filter=Stopper)
    if SaveName != None:
        TempPath = pathlib.Path(SaveDir)
        Full_Path = TempPath / SaveName
        Full_Path = Full_Path.parent / f"{Full_Path.name}.txt"
        ForFile = "\n".join(ForFile)
        Full_Path.write_text(ForFile,encoding ="utf-8")
        Full_Path = TempPath / SaveName
        Full_Path = Full_Path.parent / f"{Full_Path.name}.pcap"
        ForPcapSave = scapy.plist.PacketList(ForPcapSave)
        wrpcap(str(Full_Path),ForPcapSave)

def Sniff_Forever(Interface):
    def Stopper(Packet):
        return False
    def Filterer(Packet):
        if IP in Packet and (TCP in Packet or UDP in Packet):
            return Packet
    def Processor(Packet):
        Data = f"I Got A Packet From {Packet[IP].src} From Source Port:{Packet[IP].sport} To Destination Port:{Packet[IP].dport}"
        print(Data)
    sniff(iface="{}".format(Interface),store = 0, prn=Processor, lfilter=Filterer, stop_filter=Stopper)

def Sorting_Streams(Packets):
    def Get_Packet_Time(packetlist):
        return packetlist[0].time
    SortedPacketLists = sorted(Packets.sessions().values(), key = Get_Packet_Time)
    SortedPacketStreams = [scapy.plist.PacketList(Stream) for Stream in SortedPacketLists]
    return SortedPacketStreams

def Merging_Streams(SortedStreams):
    Streams = [] 
    visited = set()
    
    for i, eachstream in enumerate(SortedStreams):
        if len(eachstream) == 0 or i in visited:
            continue
        Temp = list(eachstream)  # ← avoid reference issues

        if (eachstream[0].haslayer(TCP) or eachstream[0].haslayer(UDP)) and eachstream[0].haslayer(IP):
            MatchPlacmentFirst = {
                "Source": eachstream[0].src,
                "Dest": eachstream[0].dst,
                "Sport": eachstream[0].sport,
                "Dport": eachstream[0].dport
            }
        else:
            continue

        for h, eachforward in enumerate(SortedStreams[i+1:], i+1):
            if len(eachforward) == 0 or h in visited:
                continue
            MatchPlacments = [
                eachforward[0].src,
                eachforward[0].dst,
                eachforward[0].sport,
                eachforward[0].dport
            ]
            if (
                MatchPlacmentFirst["Source"] == MatchPlacments[0] and
                MatchPlacmentFirst["Dest"] == MatchPlacments[1] and
                MatchPlacmentFirst["Sport"] == MatchPlacments[2] and
                MatchPlacmentFirst["Dport"] == MatchPlacments[3]
            ) or (
                MatchPlacmentFirst["Source"] == MatchPlacments[1] and
                MatchPlacmentFirst["Dest"] == MatchPlacments[0] and
                MatchPlacmentFirst["Sport"] == MatchPlacments[3] and
                MatchPlacmentFirst["Dport"] == MatchPlacments[2]
            ):
                Temp.extend(eachforward)
                visited.add(h)

        visited.add(i)
        Streams.append(Temp)

    return Streams

                
def Following_Tcp_Stream_From_Pcap(PacketStreams, StreamNumber):
    RawData = []
    TemporaryPacketStream = PacketStreams[StreamNumber]

    for pkt in TemporaryPacketStream:
        if pkt.haslayer(Raw):
            RawData.append(pkt[Raw].load)
        elif pkt.haslayer(DNS):
            RawData.append(bytes(pkt[DNS]))  

    RawDataString = b"".join(RawData)
    return RawDataString, TemporaryPacketStream

def Writing_Raw_Data(RawData,FullPath):
    Path = FullPath / "RawData.txt"
    CleanData = RawData.strip(b'\x00')
    Path.write_text(CleanData.decode("utf-8", errors="ignore"), encoding="utf-8")

def Identifying_Protocol(RawData,PacketStream):
    Protocol = ""
    def DataShowed():
        StreamCheck = str(input("Do You Want To See The Data Of The Specified Stream:[Y/N]: "))
        if StreamCheck in ["Y","N"]:
            if StreamCheck == "Y":
                return True
            else:
                return False
        else:
            return False 
        
    def HTTP(RawData,PacketStream):
        nonlocal Protocol
        RequestTypes = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]
        HTTP_Headers = [
                "Host","User-Agent","Accept","Content-Type","Content-Length",
                "Connection","Transfer-Encoding","Cache-Control","Set-Cookie","Server"
            ]
        if re.search(rb"HTTP/\d\.\d", RawData):
            for eachtype in RequestTypes:
                if re.match(rb"^" + eachtype + rb"\s", RawData):
                    Protocol = "HTTP"
                    return True
            if re.match(rb"^HTTP/\d\.\d \d{3}", RawData):
                Protocol = "HTTP"
                return True
            Count = 0
            for eachidentifier in HTTP_Headers:
                if re.match(rb"\r\n" + eachidentifier):
                    Count+=1
            if Count > 3:
                Protocol = "Likely HTTP"
                return True
        return False
    
    def DNS_Check(RawData, PacketStream):
        nonlocal Protocol
        try:
            if len(RawData) < 12:
                return False
            for pkt in PacketStream:
                if pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    if (udp.sport == 53 or udp.dport == 53):
                        dns = DNS(RawData)
                        if dns.qdcount > 0 and dns.ancount >= 0:
                            flags = int.from_bytes(dns[2:4],"big")
                            opcode = (flags >> 11) & 0b1111
                            if opcode in range(0,16):
                                Protocol = "DNS"
                                break
                elif pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    if len(RawData) >= 14:
                        length = int.from_bytes(RawData[0:2], "big")
                        if length == len(RawData) - 2 :
                            dns = DNS(RawData[2:]) 
                        else:
                            dns = DNS(RawData)
                    if tcp.sport == 53 or tcp.dport == 53:
                        if dns.qdcount > 0 and dns.ancount >= 0:
                            flags = int.from_bytes(dns[2:4],"big")
                            opcode = (flags >> 11) & 0b1111
                            if opcode in range(0,16):
                                Protocol = "DNS"
                                break
            if Protocol != "DNS":
                try:
                    dns = DNS(RawData)
                    if dns.qdcount > 0 and dns.qclass < 65535 and dns.qtype <65535:
                        Protocol = "DNS"
                except:
                    return False
            if Protocol == "DNS":
                buffer = io.StringIO()
                sys.stdout = buffer
                dns.show()
                sys.stdout = sys.__stdout__
                Temp = buffer.getvalue()
                buffer.close()
                pathlib.Path(r"E:\Newenv\DnsData.txt").write_text(Temp)
                pathlib.Path(r"E:\Newenv\RawData.txt").write_text(dns.summary())
                if DataShowed():
                    print(dns.show())
                return True
            return False
        except Exception as e:
            print(f"[DNS_Check] Error: {e}")
            return False

    def SMTP(RawData,PacketStream):
        nonlocal Protocol
        found_smtp_port = any(
        pkt.haslayer(TCP) and (pkt[TCP].dport in(25,465,587) or pkt[TCP].sport in (25,465,587))
        for pkt in PacketStream
        )
        if not found_smtp_port:
            return False
        SMTP_COMMANDS = [
        b"HELO", b"EHLO", b"MAIL FROM", b"RCPT TO", b"DATA", b"QUIT",
        b"RSET", b"NOOP", b"VRFY", b"EXPN", b"HELP", b"STARTTLS",
        b"AUTH", b"AUTH LOGIN", b"AUTH PLAIN", b"AUTH CRAM-MD5"
        ]
        Regex = rb"^220 [\w\.\d]+ .*SMTP"
        if re.match(Regex,RawData):
            Protocol = "SMTP"
            return True
        for eachsmtp in SMTP_COMMANDS:
            if re.match(rb"^" + eachsmtp + rb"\s",RawData):
                Protocol = "SMTP"
                return True
        return False
    
    def SSH(RawData,PacketStream):
        nonlocal Protocol
        found_ssh_port = any(
        pkt.haslayer(TCP) and pkt[TCP].dport == 22
        for pkt in PacketStream
        )
        if not found_ssh_port:
            return False
        Regex = rb"^SSH-\d\.\d"
        if re.match(Regex,RawData):
            Protocol = "SSH"
            return True
        return False
    
    def SMB(RawData,PacketStream):
        nonlocal Protocol
        found_smb_port = any(
        pkt.haslayer(TCP) and pkt[TCP].dport in(445,139)
        for pkt in PacketStream
        )
        if not found_smb_port or len(RawData)<8:
            return False
        smb_raw = RawData[4:8]
        Smb_Type = [b"\xffSMB",b"\xfeSMB"]
        for eachtype in Smb_Type:
            if smb_raw == eachtype :
                Protocol = "SMB"
                return True
        if RawData[:4] in Smb_Type:
            Protocol = "SMB"
            return True
        return False

    def TLS(RawData,PacketStream):
        nonlocal Protocol
        if len(RawData) == 0:
            return False
        def random_raw_data(RawData):
            Freq = [0] * 256
            for eachbyte in RawData:
                Freq[eachbyte] +=1
            Propapilty = [prob / len(RawData) for prob in Freq if prob > 0]
            x = -sum(p* math.log2(p) for p in Propapilty)
            return -sum(p* math.log2(p) for p in Propapilty)
        
        def is_encrypted(RawData, Threshold = 6.0):
            return random_raw_data(RawData) > Threshold

        found_https_port = any(
        pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443)
        for pkt in PacketStream
        )
        if not found_https_port:
            return False
        Tls_RawCheck = [b"\x14", b"\x15", b"\x16", b"\x17"]
        Tls_Version = [b"\x16\x03\x01",b"\x16\x03\x02",b"\x16\x03\x03",b"\x16\x03\x04"]
        tls_raw = RawData[0:3]
        for eachversion in Tls_Version:
            if tls_raw == eachversion :
                Protocol = "TLS/SSL"
                return True
        if RawData[0] in Tls_RawCheck and RawData[1] == b"0x03":
            Protocol = "TLS/SSL"
            return True
        if is_encrypted(RawData):
            Protocol = "TLS/SSL"
            return True
        return False
    
    def Hanshake_Only(PacketStream):
        if len(PacketStream)  != 3:
            return False
        flags_seq = []
        for eachpacket in PacketStream:
            if eachpacket.haslayer(TCP):
                tcp = eachpacket[TCP]
                if tcp.haslayer(Raw):
                    return False
                flags = tcp.flags
                flags_seq.append(flags)
        if (flags_seq[0] & 0x02 and               #SYN
        flags_seq[1] & 0x12 == 0x12 and       #SYN + ACK
        flags_seq[2] & 0x10 and not flags_seq[2] & 0x02):  #ACK only
            return True
        return False
    
    if HTTP(RawData,PacketStream) or DNS_Check(RawData,PacketStream) or SMTP(RawData,PacketStream) or SSH(RawData,PacketStream) or SMB(RawData,PacketStream) or TLS(RawData,PacketStream):
        print(f"The Identifiead Protocol is: {Protocol}")
        return Protocol
    elif Hanshake_Only(PacketStream):
        print("This Is A Full TCP Handshake Stream")
    else:
        print("The Identifiead Protocol is: Unknown")
        print(f"Here is the full data that couldnt be identified {RawData}")  

def Check_For_Layer_Tcp(Packet):
    return Packet.haslayer(TCP)

def Check_For_Layer_Udp(Packet):
    return Packet.haslayer(UDP)

def Check_For_Layer_ICMP(Packet):
    return Packet.haslayer(ICMP)

def Check_For_Layer_IP(Packet):
    return Packet.haslayer(IP)

def Check_For_Layer_Ether(Packet):
    return Packet.haslayer(Ether)

def Check_For_Raw_Data(Packet):
    return Packet.haslayer(Raw)

def Check_For_Fragments_For_Each_Packet(Packet):
    if Packet.haslayer(IP):
        ip = Packet[IP]
        mf_flag = ip.flags.MF
        frag_offset = ip.frag
        return mf_flag or frag_offset > 0
    return False

def Third_Mode(SortedStreams, StreamNumber):
    FullPath = pathlib.Path(r"E:\Newenv")
    Data, PacketStream = Following_Tcp_Stream_From_Pcap(SortedStreams, StreamNumber)
    Writing_Raw_Data(Data, FullPath)
    print("Your Stream Raw Data Has Been Written To The Default Directory\nIdentifying Protocol\n")
    Protocol = Identifying_Protocol(Data, PacketStream)
    return Protocol

def Get_Sorted_Streams_From_Pcap(PcapFirst):
    found_fragments = any(
        Check_For_Fragments_For_Each_Packet(eachpacket)
        for eachpacket in PcapFirst
    )
    if found_fragments:
        Pcap = defragment(PcapFirst)
    else:
        Pcap = PcapFirst

    NoBadChksumPcap = Remove_Bad_Checksums(Pcap)
    UniquePackets = Removing_Tcp_Duplicates(NoBadChksumPcap)
    SortedPackets = Sorted_Tcp_Packets(UniquePackets)
    SortedStreams = Sorting_Streams(SortedPackets)
    return SortedStreams

def SignatureLists(Protocol):
    def SMTPCheck():
        Signatures = [{
            "Name":"Misalignment (DMARC)",
            "Alarm": "The From And Header(MAIL FROM) are Misalgined (Possible Phishing).",
            "Code": "SMTP01",
        }]
        return Signatures
    
    def DNS():
        Signatures = [
            {
            "Name":"Top Level Domain Activity",
            "Alarm": "Top Level Domain Falls Into The List Of Likely Malicious Activity.",
            "Code": "DNS01",
            "Regex":["country","stream","download","xin",
                     "gdn","racing","jetzt","win","bid",
                     "vip","ren","kim","loan","mom","party",
                     "review","trade","date","wang"
            ]
            },
            {
            "Name":"Reputation",
            "Alarm": "Domain Reputation Is Caregtorized As Malicious.",
            "Code": "DNS02",
            },
            {
            "Name":"Age Of Domain",
            "Alarm": "Age Of Domain Is Really Recent Could Be Linked To Malicious Activity.",
            "Code": "DNS03"   
            }]
        return Signatures
    
    def HTTPCheck():
        Signatures = [
        {
            "Name": "Reputation",
            "Alarm": "Domain Reputation Is Categorized As Malicious.",
            "Code": "HTTP01"
        },
        {
            "Name": "User-Agent Activity",
            "Alarm": "User-Agent Is Categorized Malicious.",
            "Code": "HTTP02",
            "Bad-User-Agents": r"E:\Newenv\bad-user-agents.list"
        },
        {
            "Name": "Cookie Activity",
            "Alarm": "Cookie Length Is Too Long Probably Base64 Encoded Malicious Data.",
            "Code": "HTTP03",
            "Length Accepted": 2048
        },
        {
            "Name": "POST Activity",
            "Alarm": "Too Many Post Request In One Single Stream.",
            "Code": "HTTP04",
            "Accepted Count" : 100
        }
    ]
        return Signatures
    if Protocol == "DNS":
        DnsSignatures = DNS()
        return DnsSignatures
    elif Protocol == "HTTP":
        Httpsignatures = HTTPCheck()
        return Httpsignatures
    elif Protocol == "SMTP":
        Smtpsignatures = SMTPCheck()
        return Smtpsignatures

def CheckingForMaliciousActivity(Protocol):

    def DNSChecking():
        def dnstriger(PathAlarm):
            print(f"############# {eachsignature["Alarm"]} ########################")
            Data = open(PathAlarm,"a")
            Data.write(f"A Dns Query For A Malicious Domain Was Done On {time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())}\nAlarm Code: {eachsignature['Code']}\nName: {eachsignature['Name']}\nDomain: {matchcheck}\n\n")
            Data.close()
            return  
        Signatures = SignatureLists(Protocol)
        for Index,eachsignature in enumerate(Signatures):
            if Index == 0:
                Regex = eachsignature["Regex"]
                Path = pathlib.Path(r"E:\Newenv\DnsData.txt")
                Data = Path.read_text()
                matchcheck = re.findall(r"qname.+?\'([\w\d\.]+)'",Data)
                matchcheck = str(matchcheck)
                if matchcheck:
                    tld = re.findall(r"([\w\d]+)\S",matchcheck)
                    tld = tld[-1]
                    for eachregex in Regex:
                        if eachregex == tld:
                            Path = pathlib.Path(r"E:\Newenv\Alarms.txt")
                            dnstriger(Path)
                            break
            elif Index == 1:
                Path = pathlib.Path(r"E:\Newenv\DnsData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_text()
                matchcheck = re.findall(r"qname.+?\'([\w\d\.]+)'",Data)
                matchcheck = matchcheck[0][:-1]
                result = subprocess.run([
                    "curl.exe",
                    "--request",
                    "GET",
                    "--url", f"https://www.virustotal.com/api/v3/domains/{matchcheck}",
                    "--header",
                    "x-apikey: ####################Api##########################"
                ],capture_output=True,text=True)
                data = json.loads(result.stdout)
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']
                reputation = data['data']['attributes']['reputation']
                malicious_indicators = ["malware", "phishing", "trojan", "spyware", "ransomware", "exploit-kit", "botnet"]
                tags = data['data']['attributes']['tags']
                if last_analysis_stats['malicious'] > 0 :
                    dnstriger(PathAlarm)
                    break
                if last_analysis_stats['suspicious']>= 2:
                    dnstriger(PathAlarm)
                    break
                if reputation < 0:
                    dnstriger(PathAlarm)
                    break
                for eachtag in malicious_indicators:
                    if eachtag in tags:
                        dnstriger(PathAlarm)
                        break
            elif Index == 2:
                Path = pathlib.Path(r"E:\Newenv\DnsData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_text()
                matchcheck = re.findall(r"qname.+?\'([\w\d\.]+)'",Data)
                matchcheck = matchcheck[0][:-1]
                result = subprocess.run([
                    "curl.exe",
                    "--request",
                    "GET",
                    "--url", f"https://www.virustotal.com/api/v3/domains/{matchcheck}",
                    "--header",
                    "x-apikey: ####################Api##########################"
                ],capture_output=True,text=True)
                data = json.loads(result.stdout)
                creation_data = data['data']['attributes']['creation_date']
                date = datetime.datetime.fromtimestamp(creation_data)
                time_of_creation = date.strftime("%Y-%m-%d %H:%M:%S")
                mytime = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())
                if int(mytime[:4]) - int(time_of_creation[:4]) == 0:
                    if int(mytime[5:7]) - int(time_of_creation[5:7]) == 0:
                        if abs(int(mytime[8:10]) - int(time_of_creation[8:10]))<30:
                            dnstriger(PathAlarm) 
                            break
            else:
                break
        
    def HTTPCheck():
        def httptrigger(PathAlarm):
            print(f"############# {eachsignature["Alarm"]} ########################")
            Data = open(PathAlarm,"a")
            Data.write(f"A HTTP Request For A Malicious Domain Was Done On {time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())}\nAlarm Code: {eachsignature['Code']}\nName: {eachsignature['Name']}\nDomain: {matchcheck}\n\n")
            Data.close()
            return    
        Signatures = SignatureLists(Protocol)
        for Index,eachsignature in enumerate(Signatures):
            if Index == 0:
                Path = pathlib.Path(r"E:\Newenv\RawData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_bytes().decode()
                matchcheck = re.findall(r"Host: ([\w\d\.]+)\r",Data)
                matchcheck = list(set(matchcheck))
                for eachhost in matchcheck:
                    result = subprocess.run([
                        "curl.exe",
                        "--request",
                        "GET",
                        "--url", f"https://www.virustotal.com/api/v3/domains/{eachhost}",
                        "--header",
                        "x-apikey: ####################Api##########################"
                    ],capture_output=True,text=True)
                    data = json.loads(result.stdout)
                    last_analysis_stats = data['data']['attributes']['last_analysis_stats']
                    reputation = data['data']['attributes']['reputation']
                    malicious_indicators = ["malware", "phishing", "trojan", "spyware", "ransomware", "exploit-kit", "botnet"]
                    tags = data['data']['attributes']['tags']
                    if last_analysis_stats['malicious'] > 0 :
                        httptrigger(PathAlarm)
                        break
                    if last_analysis_stats['suspicious']>= 2:
                        httptrigger(PathAlarm)
                        break
                    if reputation < 0:
                        httptrigger(PathAlarm)
                        break
                    for eachtag in malicious_indicators:
                        if eachtag in tags:
                            httptrigger(PathAlarm)
                            break
            elif Index == 1:
                Path = pathlib.Path(r"E:\Newenv\RawData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_bytes().decode()
                PathAgents = pathlib.Path(eachsignature["Bad-User-Agents"])
                DataAgents = PathAgents.read_text().split("\n")
                DataAgents.remove('')
                UserAgent = re.findall(r"(User-Agent: .*?)\r",Data)
                count = 0
                for eachdata in DataAgents:
                    for eachuser in UserAgent:
                        if eachdata in eachuser:
                            httptrigger()
                            count+=1
                            break
                    if count > 0:
                        break
            elif Index == 2:
                Path = pathlib.Path(r"E:\Newenv\RawData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_bytes().decode()
                AcceptedCookieLength = eachsignature["Length Accepted"]
                CookieField = re.findall(r"Cookie: (.*?)\r",Data)
                for eachcookie in CookieField:
                    if len(eachcookie) > AcceptedCookieLength:
                        httptrigger(PathAlarm)
                        break
            elif Index == 3:
                Path = pathlib.Path(r"E:\Newenv\RawData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_bytes().decode()
                AcceptedPostRequestLength = eachsignature["Accepted Count"]
                Posts = re.findall(r"POST",Data)
                if len(Posts) > AcceptedPostRequestLength:
                    httptrigger(PathAlarm)
                    break

    def SMTPCheck():
        def smtptrigger(PathAlarm):
            print(f"############# {eachsignature["Alarm"]} ########################")
            Data = open(PathAlarm,"a")
            Data.write(f"Possible Malicous Mail Activity Was Done On {time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())}\nAlarm Code: {eachsignature['Code']}\nName: {eachsignature['Name']}\nMAIL FROM: {MAILFROM}\n\n")
            Data.close()
            return    
        Signatures = SignatureLists(Protocol)
        for Index,eachsignature in enumerate(Signatures):
            if Index == 0:
                Path = pathlib.Path(r"E:\Newenv\RawData.txt")
                PathAlarm = pathlib.Path(r"E:\Newenv\Alarms.txt")
                Data = Path.read_text()
                MAILFROM = re.findall("MAIL FROM:<(.*?)>",Data)
                FROM = re.findall(r"From:.*?\<(.*?)>",Data)
                if MAILFROM and FROM:
                    if MAILFROM != FROM:
                        smtptrigger(PathAlarm)
                        break
                else:
                    break
            else:
                break

    if Protocol == "DNS":
        DNSChecking()
    elif Protocol == "HTTP":
        HTTPCheck()
    elif Protocol == "SMTP":
        SMTPCheck()



DEFAULT_OUTPUT_DIR = pathlib.Path.cwd() / "output"
def main():
    parser = argparse.ArgumentParser(description="Cross-Platform Simple IDS Tool")
    parser.add_argument("--mode", "-m", type=int, choices=[1, 2, 3], required=True, help="Mode: 1 = Sniff Seconds, 2 = Sniff Forever, 3 = Investigate PCAP")
    parser.add_argument("--interface", "-i", type=str, help="Network interface name")
    parser.add_argument("--time", "-t", type=int, help="Number of seconds to sniff (for mode 1)")
    parser.add_argument("--save", "-s", type=str, help="Filename to save sniffed data")
    parser.add_argument("--pcap", "-p", type=str, help="Path to PCAP file (for mode 3)")
    parser.add_argument("--stream", "--stream-number", type=int, help="Stream number to follow (for mode 3)")
    parser.add_argument("--output", "-o", type=str, help="Directory to write outputs (default: ./output)")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output) if args.output else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == 1:
        if not args.interface or not args.time:
            print("[!] Mode 1 requires --interface and --time")
            return
        filename = args.save if args.save else "Last"
        Sniff_For_Seconds(args.interface, args.time, filename,output_dir)

    elif args.mode == 2:
        if not args.interface:
            print("[!] Mode 2 requires --interface")
            return
        Sniff_Forever(args.interface)

    elif args.mode == 3:
        if not args.pcap:
            print("[!] Mode 3 requires --pcap path")
            return
        PathOfPcap = pathlib.Path(args.pcap)
        if PathOfPcap.exists():
            Pcap = rdpcap(str(PathOfPcap))
            SortedStreamsUnmerged = Get_Sorted_Streams_From_Pcap(Pcap)
            SortedStreams = Merging_Streams(SortedStreamsUnmerged)
            print(f"\nTotal Streams Found: {len(SortedStreams)}")
            for i, stream in enumerate(SortedStreams, 1):
                if len(stream) == 0:
                    continue
                first_packet = stream[0]
                if first_packet.haslayer(IP) and first_packet.haslayer(TCP):
                    print(f"Stream {i}: {first_packet[IP].src}:{first_packet[TCP].sport} → {first_packet[IP].dst}:{first_packet[TCP].dport} (Packets: {len(stream)})")
                else:
                    print(f"Stream {i}: Non-TCP or malformed stream")

            StreamNum = args.stream
            if not StreamNum:
                try:
                    StreamNum = int(input("\nEnter the Stream Number You Want To Follow: "))
                except ValueError:
                    print("Invalid input. Please provide a number.")
                    return

            if 1 <= StreamNum <= len(SortedStreams):
                Protocol = Third_Mode(SortedStreams, StreamNum - 1)
                CheckingForMaliciousActivity(Protocol)
            else:
                print("Invalid stream number.")
        else:
            print("[!] PCAP file does not exist.")

if __name__ == "__main__":
    main()
