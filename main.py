from scapy import all as scapy
import tkinter as tk
import tkinter.messagebox as tkmessagebox
import re
import threading
import csv
import datetime

class Nethunter: 
    def __init__(self, root):
        self.root = root
        
        
    def app(self):
        self.root.title("Nethunter")
        self.root.geometry("800x800")

        self.bg_image = tk.PhotoImage(file=r"Background.png")

        self.bg_label = tk.Label(self.root, image=self.bg_image)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.canvas = tk.Canvas(self.root, width=300, height=250, bg='light blue', highlightthickness=0)
        self.canvas.place(relx=0.5, rely=0.5, anchor='center')
        self.canvas.create_rectangle(10, 10, 290, 240, outline="black",  width=2, )

        self.frame = tk.Frame(self.canvas, bg='light blue' )
        self.frame.place(relx=0.5, rely=0.5, anchor='center')

        self.netlabel = tk.Label(self.frame, text="Network:", bg='light blue')
        self.netlabel.grid(row=0, column=0, padx=10, pady=10)
        self.netentry = tk.Entry(self.frame)
        self.netentry.grid(row=0, column=1, padx=10, pady=10)

        self.scan_type = tk.StringVar(value="network")

        self.network_radio = tk.Radiobutton(self.frame, text="Network Scan", variable=self.scan_type, value="network", bg='light blue')
        self.network_radio.grid(row=3, column=0)

        self.port_radio = tk.Radiobutton(self.frame, text="Port Scan", variable=self.scan_type, value="port", bg='light blue')
        self.port_radio.grid(row=3, column=1)


        self.button = tk.Button(self.frame, text="Scan", command=lambda: self.scan_network(self.netentry.get()))
        self.button.grid(row=4, column=0, columnspan=2)

        self.action = tk.Text(self.frame, height=1, width=30, bg='light blue', bd=0, wrap=tk.WORD)
        self.action.grid(row=5, column=0, columnspan=2)


    def scan_network(self, netID):

        #print(netID, subnet, deviceID)

        self.Network = netID

        Subnetscan = r'\b\d{1,3}\.\d{1,3}\b'
        netscan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        devicescan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        portscan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b'

        if self.scan_type == 'port' and re.match(portscan, self.Network):
            portscan()
            return
        
        if re.match(devicescan, self.Network):
            #print("device Scan")
            self.devicescan()
        elif re.match(netscan, self.Network):
            #print("network Scan")
            self.Netscan()
        elif re.match(Subnetscan, self.Network):
            #print("Subnet Scan")
            self.Subnetscan()
        else:
            tkmessagebox.showerror("Error", "Invalid IP address")
       
    
    def Netscan(self):
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

    def run_scan(self):
        try:
            clients_list = []
            for i in range(1, 255):
                ip = f'{self.Network}.{str(i)}'
                self.action.delete(1.0, tk.END)
                self.action.insert(tk.END, f"Scanning {ip}")
                self.action.update_idletasks()
                arp_request = scapy.ARP(pdst=ip)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                for element in answered_list:
                    client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                    clients_list.append(client_dict)

            now = datetime.datetime.now()
            date = now.strftime("%Y%m%d%H%M%S")
                    
            with open(f'clients_list{str(date)}.csv', 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=["ip", "mac"])
                writer.writeheader()
                writer.writerows(clients_list)

            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning complete. Results saved to clients_list.csv")
            self.action.update_idletasks()
        except Exception as e:
            print(f"An error occurred: {e}")

    def devicescan(self):
        arp_request = scapy.ARP(pdst=self.Network)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        now = datetime.datetime.now()
        date = now.strftime("%Y%m%d%H%M%S") 

        with open(f'clients_list{str(date)}.csv', 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["ip", "mac"])
            writer.writeheader()
            writer.writerows(clients_list)

        self.action.delete(1.0, tk.END)
        self.action.insert(tk.END, f"Scanning complete. Results saved to clients_list.csv")
        self.action.update_idletasks()
        

    def portscan(self):
        scan_thread = threading.Thread(target=self.run_port_scan)
        scan_thread.start()

    def run_port_scan(self):
        open_ports = []
        try:
            for port in range(1, 1025):
                s = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
                self.action.delete(1.0, tk.END)
                self.action.insert(tk.END, f"Scanning Port: {port}")
                self.action.update_idletasks()
                s.settimeout(1)
                result = s.connect_ex((self.Network, port))
                if result == 0:
                    open_ports.append(port)
                    #print(f"Port {port} is open")
                s.close()

            now = datetime.datetime.now()
            date = now.strftime("%Y%m%d%H%M%S")
            
            with open(f'open_ports{str(date)}.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(open_ports)

            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning complete")
            self.action.update_idletasks()
        
        except Exception as e:
            print(f"An error occurred: {e}")

    def run_subnet_scan(self):
        arp = scapy.ARP(pdst=self.Network)
        ether = ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = scapy.srp(packet, timeout=3, verbose=0)[0]

        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        now = datetime.datetime.now()
        date = now.strftime("%Y%m%d%H%M%S")
            
        with open(f'Subnets{str(date)}.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(devices)

        self.action.delete(1.0, tk.END)
        self.action.insert(tk.END, f"Scanning complete")
        self.action.update_idletasks()

    def Subnetscan(self):
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = Nethunter(root)
    app.app()
    root.mainloop()