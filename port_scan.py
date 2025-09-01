import socket
from datetime import datetime
import sys
import argparse
# target=input("Enter The Host Name You Need To Scan OR The IP Address : ")

def port_scan(target,start,end):
    try:
        ip=socket.gethostbyname(target)
        print(f"Scaning The IP Address {ip}")
        print(f"Started At Time : {datetime.now()}")
        for port in range(start,end+1):
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(0.5)
            res=s.connect_ex((ip,port))
        
            if res==0:
              try:   
                service=socket.getservbyport(port,"tcp")
                print(f"Opening Port {port} And The Protocl Service is : {service}")
              except OSError:
                print(f"Closed Port {port} And The Protocl Service is Unknown")
              
            
                
    except socket.gaierror:
        print("Cannot Opening Port !")
    except socket.error:
        return

# if __name__=="__main__":
#     parser=argparse.ArgumentParser(description="Port Scan Tool")
#     parser.add_argument('-t','--target',required=True,help='The Address of Ip')
#     parser.add_argument('-p','--ports',default='1-1024',help='Port Need To Scan')
#     args=parser.parse_args()
    
#     try:
#         port_range=args.ports.split('-')
#         start=int(port_range[0])
#         end=int(port_range[1])
#     except:
#         print("The Syntax of using was error")
#         sys.exit()
    
#     port_scan(args.target,start,end)
        