#! /usr/bin/env/python

import sys
import re
import threading
from scapy.all import *
import Tkinter as tk



class Application(tk.Frame): 
    switchDHCP = False
    switchARP = False
    threadDHCP = None
    threadARP = None 
    initial_MACs = []
    found_MACs_ICMP = []
    found_MACs_DHCP = []
    found_MACs_ARP = []


    def __init__(self, master=None):
        tk.Frame.__init__(self, master)   
        self.grid()                       
        self.createWidgets()

    def createWidgets(self):
        self.labelNet = tk.Label(self, text="Network IP and netmask (CIDR notation: 'x.x.x.x/y'): ")
        self.labelNet.grid(column=0, row=0)
        self.textNet = tk.Entry(self)
        self.textNet.grid(column=1, row=0)


        self.labelInit = tk.Label(self, text="Found with ICMP requests:")
        self.labelInit.grid(column=0, row=2, columnspan=2)
        self.canvasInit = tk.Canvas(self)
        self.canvasInit.grid(column=0, row=3, columnspan=2, rowspan=10)
        self.textInit = tk.Text(self.canvasInit, bg='black', fg='green')
        self.textInit.config(state='disabled')
        self.textInit.grid(column=0, row=3, columnspan=2, rowspan=10)
        self.initButton = tk.Button(self, text='Initial ICMP request batch',
            command=self.initial_collect)            
        self.initButton.grid(column=0, row=13)
        self.timerScanButton = tk.Button(self, text='Send requests every 30 seconds',
            command=self.icmptimer)            
        self.timerScanButton.grid(column=1, row=13)
        self.timerScanStopButton = tk.Button(self, text='Stop sending requests',
            command=self.icmptimer)            
        self.timerScanStopButton.grid(column=1, row=14)

        self.labelDhcp = tk.Label(self, text="Sniffed DHCP:")
        self.labelDhcp.grid(column=2, row=2, columnspan=2)
        self.canvasDhcp = tk.Canvas(self)
        self.canvasDhcp.grid(column=2, row=3, columnspan=2, rowspan=10)
        self.textDhcp = tk.Text(self.canvasDhcp, bg='black', fg='red')
        self.textDhcp.config(state='disabled')
        self.textDhcp.grid(column=2, row=3, columnspan=2, rowspan=10)
        self.dhcpButton = tk.Button(self, text='Sniff DHCP',
            command=lambda: self.start_button("DHCP"))            
        self.dhcpButton.grid(column=2, row=13, columnspan=2)
        self.dhcpStopButton = tk.Button(self, text='Stop sniffing',
            command=lambda: self.stop_button("DHCP"))            
        self.dhcpStopButton.grid(column=2, row=14, columnspan=2)

        self.labelArp = tk.Label(self, text="Sniffed ARP:")
        self.labelArp.grid(column=4, row=2, columnspan=2)
        self.canvasArp = tk.Canvas(self)
        self.canvasArp.grid(column=4, row=3, columnspan=2, rowspan=10)
        self.textArp = tk.Text(self.canvasArp, bg='black', fg='red')
        self.textArp.config(state='disabled')
        self.textArp.grid(column=4, row=3, columnspan=2, rowspan=10)
        self.arpButton = tk.Button(self, text='Sniff ARP',
            command=lambda: self.start_button("ARP"))            
        self.arpButton.grid(column=4, row=13, columnspan=2)
        self.arpStopButton = tk.Button(self, text='Stop sniffing',
            command=lambda: self.stop_button("ARP"))            
        self.arpStopButton.grid(column=4, row=14, columnspan=2)


        # self.quitButton = tk.Button(self, text='Quit',
        #     command=self.quit)            
        # self.quitButton.grid(column=2, row=16, columnspan=2)
        
    def stop_sniffing(self, packet, type):
        if (type=='DHCP'):
            return self.__class__.switchDHCP
        elif(type=='ARP'):
            return self.__class__.switchARP

    def stop_button(self, type):
        if (type=='DHCP'):
            self.__class__.switchDHCP = True
            print('DEBUG: stoping ' +type)
        elif(type=='ARP'):
            self.__class__.switchARP = True
            print('DEBUG: stoping ' +type)

    def start_button(self, type):
        if (type=='DHCP'):
            if (self.__class__.threadDHCP is None) or (not self.__class__.threadDHCP.is_alive()):
                self.__class__.switchDHCP = False
                self.__class__.threadDHCP = threading.Thread(target=self.sniff_dhcp)
                self.__class__.threadDHCP.start()
            else:
                print('DEBUG: already running DHCP')
        elif(type=='ARP'):
            if (self.__class__.threadARP is None) or (not self.__class__.threadARP.is_alive()):
                self.__class__.switchARP = False
                self.__class__.threadARP = threading.Thread(target=self.sniff_arp)
                self.__class__.threadARP.start()
            else:
                print('DEBUG: already running ARP')

    def text_insert_entry(self, type, entry):
        if(type=='INIT'):
            self.textInit.config(state='normal')
            self.textInit.insert('end', entry)
            self.textInit.insert('end', '\n')
            self.textInit.config(state='disabled')
        elif (type=='DHCP'):
            self.textDhcp.config(state='normal')
            self.textDhcp.insert('end', entry)
            self.textDhcp.insert('end', '\n')
            self.textDhcp.config(state='disabled')
        elif(type=='ARP'):
            self.textArp.config(state='normal')
            self.textArp.insert('end', entry)
            self.textArp.insert('end', '\n')
            self.textArp.config(state='disabled')
        elif(type=="ICMP"):
            self.textInit.config(state='normal')
            self.textInit.insert('end', entry)
            self.textInit.tag_add("redd", 'current linestart', 'current lineend')
            self.textInit.tag_config("redd", foreground='red')
            self.textInit.insert('end', '\n')
            self.textInit.config(state='disabled')
            

    def sniff_handler(self, packet, type):
        mac = packet["Ether"].src
        if (type == "DHCP"):
            if mac not in self.__class__.found_MACs_DHCP :
                print("Found MAC: " + str(mac))
                self.__class__.found_MACs_DHCP.append(mac)
                self.text_insert_entry("DHCP", mac)
        elif(type == "ARP"):
            if mac not in self.__class__.found_MACs_ARP :
                print("Found MAC: " + str(mac))
                self.__class__.found_MACs_ARP.append(mac)
                self.text_insert_entry("ARP", mac)   

    def sniff_dhcp(self):
        print('DEBUG: before sniff DHCP')
        sniff(filter="(udp port 67) and (udp[247:4] = 0x63350103)", count=0, prn=lambda x: self.sniff_handler(x, "DHCP"), stop_filter=lambda x: self.stop_sniffing(x, "DHCP"))
        print('DEBUG: after sniff DHCP')

    def sniff_arp(self):
        print('DEBUG: before sniff ARP')
        sniff(filter="arp[6:2] == 2", count=0,prn=lambda x: self.sniff_handler(x, "ARP"), stop_filter=lambda x: self.stop_sniffing(x, "ARP"))
        print('DEBUG: after sniff ARP')

    def initial_collect(self):
        net = self.textNet.get()
        # if net=="" or net.count('.')!=3 or '/' not in net or net.upper().isupper()
        if net=="" or re.match("^[0-9./]*$", net)==None or int(net.split("/")[1]) > 30 or int(net.split(".")[0]) > 255 or int(net.split(".")[1]) > 255 or int(net.split(".")[2]) > 255 or int(net.split(".")[3].split("/")[0]) > 255 :
            return
        print("Initial search for hosts")   
        icmp = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=net)/ICMP()
        (ans, unans) = srp(icmp, multi=True, timeout=10)
        if (len(ans) == 0):
            print("Hosts not found")
        else:
            self.textInit.config(state='normal')
            self.textInit.delete('1.0', 'end')
            self.textInit.config(state='disabled')
            for p in ans:
                for packet in p:
                    if packet["ICMP"].type==0:
                        mac = packet["Ether"].src
                        print("Found MAC: " + str(mac))
                        self.__class__.initial_MACs.append(mac)
                        self.text_insert_entry("INIT", mac)

    def icmptimer(self):
        t = threading.Timer(30.0, self.icmptimer).start()
        net = self.textNet.get()
        if net=="" or re.match("^[0-9./]*$", net)==None or int(net.split("/")[1]) > 30 or int(net.split(".")[0]) > 255 or int(net.split(".")[1]) > 255 or int(net.split(".")[2]) > 255 or int(net.split(".")[3].split("/")[0]) > 255 :
            return
        print("Search for hosts")   
        icmp = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=net)/ICMP()
        (ans, unans) = srp(icmp, multi=True, timeout=10)
        if (len(ans) == 0):
            print("Hosts not found")
        else:
            for p in ans:
                for packet in p:
                    if packet["ICMP"].type==0:
                        mac = packet["Ether"].src
                        if mac in self.__class__.initial_MACs :
                            continue
                            continue
                        print("Found MAC: " + str(mac))
                        self.__class__.found_MACs_ICMP.append(mac)
                        self.text_insert_entry("ICMP", mac)
        thread.exit()


app = Application()                       
app.master.title('New hosts in net')    
app.mainloop()                            







