from scapy import all as scapy
import tkinter as tk
import tkinter.messagebox as tkmessagebox
import re
import threading
import csv
import datetime
import socket

class Nethunter: 
    def __init__(self, root):
        self.root = root
        
    
    def app(self):
        # Create the main window
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

        # Create radio buttons for scan type
        self.network_radio = tk.Radiobutton(self.frame, text="Network Scan", variable=self.scan_type, value="network", bg='light blue')
        self.network_radio.grid(row=3, column=0)

        self.port_radio = tk.Radiobutton(self.frame, text="Port Scan", variable=self.scan_type, value="port", bg='light blue')
        self.port_radio.grid(row=3, column=1)

        # Create a scan button
        self.button = tk.Button(self.frame, text="Scan", command=lambda: self.scan_network(self.netentry.get()))
        self.button.grid(row=4, column=0, columnspan=2)

        # Create a text box for the results
        self.action = tk.Text(self.frame, height=1, width=30, bg='light blue', bd=0, wrap=tk.WORD)
        self.action.grid(row=5, column=0, columnspan=2)


    # Function to scan the network based on the input provided
    def scan_network(self, netID):

        #print(netID, subnet, deviceID)

        self.Network = netID

        # Regular expressions to validate the input
        Subnetscan = r'\b\d{1,3}\.\d{1,3}\b'
        netscan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        devicescan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        portscan = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b'

        # Check the input and call the appropriate function
        if self.scan_type.get() == 'port' and re.match(portscan, self.Network):
            self.portscan()
            return
        
        # Check the input and call the appropriate function
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
       
    
    def Netscan(self): # Function to scan the network
        # Create a thread to run the scan
        scan_thread = threading.Thread(target=self.run_subnet_scan)
        scan_thread.start()

    def run_scan(self): # Function to run the scan
        try:
            clients_list = []
            for i in range(1, 255): # Loop through the IP addresses in the subnet
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
            
            # Save the results to a CSV file
            with open(f'clients_list{str(date)}.csv', 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=["ip", "mac"])
                writer.writeheader()
                writer.writerows(clients_list)

            # Display a message to the user
            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning complete. Results saved to clients_list.csv")
            self.action.update_idletasks()
        except Exception as e:
            # Display an error message if an error occurs
            print(f"An error occurred: {e}")

    def devicescan(self):
        open_ports = []
        try:
            for port in range(1, 1025):  # Loop through the ports
                s = scapy.socket.socket(scapy.socket.AF_INET, scapy.socket.SOCK_STREAM)
                self.action.delete(1.0, tk.END)
                self.action.insert(tk.END, f"Scanning Port: {port}/1025")
                self.action.update_idletasks()
                s.settimeout(1)
                result = s.connect_ex((self.Network, port))
                if result == 0:
                    open_ports.append(port)
                s.close()

            now = datetime.datetime.now()
            date = now.strftime("%Y%m%d%H%M%S")

            # Save the results to a CSV file
            with open(f'open_ports_{self.Network}_{str(date)}.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Port"])
                for port in open_ports:
                    writer.writerow([port])

            # Display a message to the user
            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning complete. Results saved to open_ports_{self.Network}_{str(date)}.csv")
            self.action.update_idletasks()

        except Exception as e:
            print(f"An error occurred: {e}")
        

    def portscan(self): # Function to scan the ports on a device
        scan_thread = threading.Thread(target=self.run_port_scan) # Create a thread to run the scan
        scan_thread.start()

    def run_port_scan(self): # Function to run the port scan
        try:
            # Extract IP address and port number from user input
            ip, port = self.Network.split(':')
            port = int(port)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning Port: {port}")
            self.action.update_idletasks()
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            
            port_info = {
                "IP": ip,
                "Port": port,
                "Status": "Open" if result == 0 else "Closed"
            }
            
            if result == 0:
                try:
                    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
                    banner = s.recv(1024).decode().strip()
                    port_info["Banner"] = banner
                    
                    # Additional information
                    service_name = socket.getservbyport(port)
                    port_info["Service"] = service_name
                    
                    # Attempt to get more detailed banner information
                    s.send(b'OPTIONS / HTTP/1.1\r\n\r\n')
                    detailed_banner = s.recv(1024).decode().strip()
                    port_info["Detailed_Banner"] = detailed_banner
                    
                except Exception as e:
                    port_info["Banner"] = "N/A"
                    port_info["Service"] = "N/A"
                    port_info["Detailed_Banner"] = "N/A"
            
            s.close()

            now = datetime.datetime.now()
            date = now.strftime("%Y%m%d%H%M%S")
            
            # Save the results to a CSV file
            with open(f'port_info_{ip}_{port}_{str(date)}.csv', 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=["IP", "Port", "Status", "Banner", "Service", "Detailed_Banner"])
                writer.writeheader()
                writer.writerow(port_info)

            # Display a message to the user
            self.action.delete(1.0, tk.END)
            self.action.insert(tk.END, f"Scanning complete. Results saved to port_info_{ip}_{port}_{str(date)}.csv")
            self.action.update_idletasks()

        except Exception as e:
            print(f"An error occurred: {e}")

    def run_subnet_scan(self): # Function to run the subnet scan
        arp = scapy.ARP(pdst=self.Network)  # Create an ARP request
        ether = ether(dst="ff:ff:ff:ff:ff:ff") # Create a broadcast frame
        packet = ether/arp # Combine the ARP request and broadcast frame

        result = scapy.srp(packet, timeout=3, verbose=0)[0]

        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        now = datetime.datetime.now()
        date = now.strftime("%Y%m%d%H%M%S")
        
        # Save the results to a CSV file
        with open(f'Subnets{str(date)}.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(devices)

        # Display a message to the user
        self.action.delete(1.0, tk.END)
        self.action.insert(tk.END, f"Scanning complete")
        self.action.update_idletasks()

    def Subnetscan(self):
        # Create a thread to run the scan
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

if __name__ == "__main__": # Main function
    root = tk.Tk()
    app = Nethunter(root)
    app.app()
    root.mainloop()