import scapy.all as scapy
import tkinter as tk
import tkinter.messagebox as tkmessagebox
import re

class Nethunter:
    def __init__(self, root):
        self.root = root
        
        
    def app(self):
        self.root.title("Nethunter")
        self.root.geometry("800x800")

        self.bg_image = tk.PhotoImage(file=r"Network-hunter\Background.png")

        self.bg_label = tk.Label(self.root, image=self.bg_image)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.netlabel = tk.Label(self.root, text="Network ID").grid(row=0, column=0)
        self.netentry = tk.Entry(self.root)
        self.netentry.grid(row=0, column=1)

        self.sublabel = tk.Label(self.root, text="Subnet:").grid(row=1, column=0)
        self.subentry = tk.Entry(self.root)
        self.subentry.grid(row=1, column=1)

        self.devlabel = tk.Label(self.root, text="Device ID").grid(row=2, column=0)
        self.deventry = tk.Entry(self.root)
        self.deventry.grid(row=2, column=1)

        self.button = tk.Button(self.root, text="Scan", command=lambda: self.scan_network(self.netentry.get(),
                                                                                         self.subentry.get(),
                                                                                         self.deventry.get()))
        self.button.grid(row=4, column=0, columnspan=2)

    def scan_network(self, netID, subnet, deviceID):

        #print(netID, subnet, deviceID)

        Network = netID + "." + subnet

        regpattern = r'\b\d{3}\.\d{3}\b'
        if netID == "" or netID == None or not re.match(regpattern, Network):
            tkmessagebox.showerror("Error", "Please enter a valid network ID")
            return
        else:
            if deviceID == "" or deviceID == None:
                self.Netscan()
            else:
                self.devicescan()
       
    
    def Netscan(self):
        clients_list = []
        for i in range(1, 255):
            ip = f'{self.netentry.get()}.{self.subentry.get()}.{str(i)}'
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            for element in answered_list:
                client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client_dict)
            
        print(clients_list)

    def devicescan(self):
        ip = self.netentry.get() + "." + self.subentry.get() + "." + self.deventry.get()
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        
        print(clients_list)
        

if __name__ == "__main__":
    root = tk.Tk()
    app = Nethunter(root)
    app.app()
    root.mainloop()