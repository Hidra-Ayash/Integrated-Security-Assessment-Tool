import re
import sys
import argparse
from collections import Counter
import math
# Define suspicious user-agent strings
SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "dirbuster",
    "w3af"
]

def analyse_file(log_file):
    failed_login=Counter()
    ip_requests=Counter()
    suspicous_user_agent=Counter()
    
    # The regular expression to parse a common log format
    # This pattern captures IP, user, date, method, path, status, and user-agent
    log_pattern=re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.*\] "(\w+) (.*) HTTP/\d\.\d" (\d{3}) (\d+) ".*" "(.*)"')
    try:
        with open(log_file,'r') as lg_file:
            for line in lg_file:
                match=log_pattern.match(line)
                if match:
                    ip,method,path,status,_,user_agent=match.groups()
                    ##Count The total request for each ip
                    ip_requests[ip]+=1
                    ##Check the Status of Request
                    if status in ['401','403']:
                        failed_login[ip]+=1
                    ##Check The Suspicous of user agent
                    if any(agent.lower() in user_agent for agent in SUSPICIOUS_USER_AGENTS):
                        suspicous_user_agent[ip]+=1
    except FileNotFoundError as fr:
        print(f"File Not Found {fr} , Please Repeait Again")
        sys.exit()
    except Exception as e:
        print(f'The Error is {e}')
        sys.exit()
    print('*'*50)
    print(f'Log Analysit Report {log_file}')
    print('*'*50)
    print('\n--- Summary ---')
    print(f'The Total of ip requests is : {sum(ip_requests.values())}')
    print(f'The Unique of ip requests is : {len(ip_requests)}')
    if ip_requests:
        for ip,count in ip_requests.most_common(5):
            print(f'\n The Count Requests  of each {ip} ---> {count}')
    if failed_login:
        for ip,count in failed_login.most_common(5):
            print(f'\n The Count of Failed Login to each {ip} ---> {count}')
    if suspicous_user_agent:
        for ip,count in suspicous_user_agent.most_common(5):
            print(f'\n The Count of user agent to each {ip} ---> {count}')
    if not suspicous_user_agent and not failed_login :
        print("\nNo suspicious activity found.")

# if __name__=="__main__":
#     parser=argparse.ArgumentParser(description='Analysis Tool Log File')
#     parser.add_argument('-f','--file',required=True,help='Add The Path of Log File')
#     args=parser.parse_args() 
#     target_file=args.file
#     analyse_file(target_file)                   


    
    