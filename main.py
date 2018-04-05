#! /usr/bin/env/python

from Tkinter import *
from scapy.all import *
from threading import Thread, Event, Timer
import re

class Sniffer(Thread):
        
        def  __init__(self, type, textfield, array):
            super(Sniffer, self).__init__()

            self.daemon = True
            self.type = type
            self.socket = None
            self.textfield = textfield
            self.array = array
            self.stop_sniffer = Event()

        def run(self):
            self.socket = conf.L2listen(
                type=ETH_P_ALL
            )

            if (self.type == "DHCP"):
                print("Sniffing DHCP")
                try:
                    sniff(
                        filter="(udp port 67) and (udp[247:4] = 0x63350103)",
                        opened_socket=self.socket,
                        prn=lambda x: self.print_packet(x, "DHCP"),
                        stop_filter=self.should_stop_sniffer
                    )
                except Exception:
                    pass
            elif(self.type == "ARP"):
                print("Sniffing ARP")
                try:
                    sniff(
                        filter="arp[6:2] == 2", 
                        opened_socket=self.socket,
                        prn=lambda x: self.print_packet(x, "ARP"),
                        stop_filter=self.should_stop_sniffer
                    )
                except Exception:
                    pass

        def join(self, timeout=None):
            if(not self.ident == None):
                print("Stopping "+self.type+" sniff")
                self.stop_sniffer.set()
                super(Sniffer, self).join(timeout)

        def should_stop_sniffer(self, packet):
            return self.stop_sniffer.isSet()

        def print_packet(self, packet, type):
            mac = packet["Ether"].src
            if mac not in self.array:
                print("Found MAC by " + str(self.type) + ": " + str(mac))
                self.array.append(mac)
                self.textfield.config(state='normal')
                self.textfield.insert('end', str(mac))
                self.textfield.insert('end', '\n')
                self.textfield.config(state='disabled')
                if (self.type == "DHCP"):
                    global dhcp_num
                    dhcp_num.set(dhcp_num.get()+1)
                elif(self.type == "ARP"):
                    global arp_num
                    arp_num.set(arp_num.get()+1)
            
class SingleRequest():
    def  __init__(self, net, textfield, array):
        self.textfield = textfield
        self.array = array
        self.net = net

    def send_batch(self):
        global init_num
        init_num.set(0)
        netip = self.net.get()
        if netip=="" or re.match("^[0-9./]*$", netip)==None or int(netip.split("/")[1]) > 30 or int(netip.split(".")[0]) > 255 or int(netip.split(".")[1]) > 255 or int(netip.split(".")[2]) > 255 or int(netip.split(".")[3].split("/")[0]) > 255 :
            print("Illegal network address")
            return
        print("Initial search for hosts")   
        icmp = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=netip)/ICMP()
        (ans, unans) = srp(icmp, multi=True, timeout=10)
        if (len(ans) == 0):
            print("Hosts not found")
        else:
            self.textfield.config(state='normal')
            self.textfield.delete('1.0', 'end')
            self.textfield.config(state='disabled')
            for p in ans:
                for packet in p:
                    if packet["ICMP"].type==0:
                        mac = packet["Ether"].src
                        print("Found MAC by initial ICMP: " + str(mac))
                        self.array.append(mac)
                        self.textfield.config(state='normal')
                        self.textfield.insert('end', str(mac))
                        self.textfield.insert('end', '\n')
                        self.textfield.config(state='disabled')
                        init_num.set(init_num.get()+1)

def cont_start_button():
    global icmp_threads_array
    if (len(icmp_threads_array) == 0):
        t = Thread(target=start_cont)
        t.setDaemon(True)
        t.start()
        icmp_threads_array.append(t)
    else:
        print "Sending continuous requests already running"                    

def start_cont():
    global icmp_threads_array
    t = Timer(30.0, start_cont)
    t.setDaemon(True)
    t.start()
    icmp_threads_array.append(t)
    global textNet
    net = textNet.get()
    if net=="" or re.match("^[0-9./]*$", net)==None or int(net.split("/")[1]) > 30 or int(net.split(".")[0]) > 255 or int(net.split(".")[1]) > 255 or int(net.split(".")[2]) > 255 or int(net.split(".")[3].split("/")[0]) > 255 :
        print("Illegal network address")
        return
    print("Continuous search for hosts")   
    icmp = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=net)/ICMP()
    (ans, unans) = srp(icmp, multi=True, timeout=10)
    if (len(ans) == 0):
        print("Hosts not found")
    else:
        global initial_MACs
        global found_MACs_ICMP
        global textInit
        global icmp_num
        for p in ans:
            for packet in p:
                if packet["ICMP"].type==0:
                    mac = packet["Ether"].src
                    if mac in initial_MACs or mac in found_MACs_ICMP:
                        continue
                        continue
                    print("Found MAC: " + str(mac))
                    found_MACs_ICMP.append(mac)
                    textInit.config(state='normal')
                    textInit.insert('end', str(mac))
                    textInit.tag_add("redd", 'current linestart', 'current lineend')
                    textInit.tag_config("redd", foreground='red')
                    textInit.insert('end', '\n')
                    textInit.config(state='disabled')
                    icmp_num.set(icmp_num.get()+1)

def cont_stop_button():
    global icmp_threads_array
    for t in icmp_threads_array:
        print t
        try:
            t.cancel()
            t.join()
        except Exception:
            pass
        if isinstance(t, Timer.__class__):
            print "is timer"
            t.cancel()
        elif isinstance(t, Thread.__class__):
            print "is thread"
            t.join()
    del icmp_threads_array[:]
    print "Stopping continuous search"


def start_button(sniffer_array, type, textfield, array):
    if (type == "DHCP"):
        if(len(sniffer_array)==0):
        # if(sniffer_DHCP.ident == None):
            sniffer_DHCP = Sniffer(type, textfield, array)
            sniffer_array.append(sniffer_DHCP)
            sniffer_array[0].start()
        else:
            print("Already sniffing DHCP")
    elif (type == "ARP"):
        if(len(sniffer_array)==0):
        # if(sniffer_ARP.ident == None):
            sniffer_ARP = Sniffer(type, textfield, array)
            sniffer_array.append(sniffer_ARP)
            sniffer_array[0].start()
        else:
            print("Already sniffing ARP")
    for s in sniffer_array:
        print s

sniffer_DHCP_array = []
sniffer_ARP_array = []

def execute_join(sniffer_array, type):
    if (type == "DHCP"):
        if (sniffer_array):
            sniffer = sniffer_array.pop(0)
            sniffer.join(1.0)
            if sniffer.isAlive():
                sniffer.socket.close()
            # sniffer_array.remove(0)
        else:
            print "Sniffing already stopped"
    elif (type == "ARP"):
        if (sniffer_array):
            sniffer = sniffer_array.pop(0)
            sniffer.join(1.0)
            if sniffer.isAlive():
                sniffer.socket.close()
            # sniffer_array.remove(0)
        else:
            print "Sniffing already stopped"
    for s in sniffer_array:
        print s


initial_MACs = []
found_MACs_ICMP = []
found_MACs_DHCP = []
found_MACs_ARP = []

icmp_threads_array = []

root = Tk()
root.title("New hosts in net")
frame = Frame().__init__
labelNet = Label(root,text="Network IP and netmask (CIDR notation: 'x.x.x.x/y'): ")
labelNet.grid(column=0, row=0)

textNet = Entry(root)
textNet.grid(column=1, row=0)

labelInit = Label(root, text="Found with ICMP requests:")
labelInit.grid(column=0, row=2, columnspan=2)

canvasInit = Canvas(root)
canvasInit.grid(column=0, row=3, columnspan=2, rowspan=10)

textInit = Text(canvasInit, bg='black', fg='green')
textInit.config(state='disabled')
textInit.grid(column=0, row=3, columnspan=2, rowspan=10)

init_ICMP = SingleRequest(textNet, textInit, initial_MACs)
# timed_ICMP = Requester(textNet, textInit, found_MACs_ICMP, initial_MACs)

labelInitSniffedInfo = Label(root, justify=LEFT, text="No. of initial MACs: ")
labelInitSniffedInfo.grid(column=0, row=13)
init_num = IntVar()
dhcp_num = IntVar()
arp_num = IntVar()
icmp_num = IntVar()
labelInitSniffedNumber = Label(root, justify=LEFT, textvariable=init_num)
labelInitSniffedNumber.grid(column=1, row=13)


labelIcmpSniffedInfo = Label(root, justify=LEFT, text="No. of MACs found from continuous requests: ")
labelIcmpSniffedInfo.grid(column=0, row=14)
labelIcmpSniffedNumber = Label(root, justify=LEFT, textvariable=icmp_num)
labelIcmpSniffedNumber.grid(column=1, row=14)

initButton = Button(root, text='Initial ICMP request batch', command= lambda: init_ICMP.send_batch())            
initButton.grid(column=0, row=15)
timerScanButton = Button(root, text='Send requests every 30 seconds', command= lambda: cont_start_button())            
timerScanButton.grid(column=1, row=15)

timerScanStopButton = Button(root, text='Stop sending requests', command= lambda: cont_stop_button())            
timerScanStopButton.grid(column=1, row=16)

labelDhcp = Label(root, text="Sniffed DHCP:")
labelDhcp.grid(column=2, row=2, columnspan=2)

canvasDhcp = Canvas(root)
canvasDhcp.grid(column=2, row=3, columnspan=2, rowspan=10)

textDhcp = Text(canvasDhcp, bg='black', fg='green')
textDhcp.config(state='disabled')
textDhcp.grid(column=2, row=3, columnspan=2, rowspan=10)

# sniffer_DHCP = Sniffer("DHCP", textDhcp, found_MACs_DHCP)

labelDhcpSniffedInfo = Label(root, justify=LEFT, text="No. of found MACs: ")
labelDhcpSniffedInfo.grid(column=2, row=13)

labelDhcpSniffedNumber = Label(root, justify=LEFT, textvariable=dhcp_num)
labelDhcpSniffedNumber.grid(column=3, row=13)

dhcpButton = Button(root, text='Sniff DHCP', command=lambda: start_button(sniffer_DHCP_array, "DHCP", textDhcp, found_MACs_DHCP))            
dhcpButton.grid(column=2, row=15, columnspan=2)

dhcpStopButton = Button(root, text='Stop sniffing', command=lambda: execute_join(sniffer_DHCP_array, "DHCP"))            
dhcpStopButton.grid(column=2, row=16, columnspan=2)

labelArp = Label(root, text="Sniffed ARP:")
labelArp.grid(column=4, row=2, columnspan=2)

canvasArp = Canvas(root)
canvasArp.grid(column=4, row=3, columnspan=2, rowspan=10)

textArp = Text(canvasArp, bg='black', fg='green')
textArp.config(state='disabled')
textArp.grid(column=4, row=3, columnspan=2, rowspan=10)

# sniffer_ARP = Sniffer("ARP", textArp, found_MACs_ARP)

labelArpSniffedInfo = Label(root, justify=LEFT, text="No. of found MACs: ")
labelArpSniffedInfo.grid(column=4, row=13)

labelArpSniffedNumber = Label(root, justify=LEFT, textvariable=arp_num)
labelArpSniffedNumber.grid(column=5, row=13)

arpButton = Button(root, text='Sniff ARP', command=lambda: start_button(sniffer_ARP_array, "ARP", textArp, found_MACs_ARP))            
arpButton.grid(column=4, row=15, columnspan=2)

arpStopButton = Button(root, text='Stop sniffing', command=lambda: execute_join(sniffer_ARP_array, "ARP"))            
arpStopButton.grid(column=4, row=16, columnspan=2)
root.mainloop()

