import requests
import sys
from urllib.parse import urlparse
import argparse



def scan_vulnabrity(url):
    print('*'*50)
    print(f"Start Scaning {url}")
    print('*'*50)
    if not url.startswith(('http://','https://')):
        url='http://'+url
    try:
        response=requests.get(url,timeout=5,allow_redirects=True)
        final_url=response.url
        if final_url.startswith('https://'):
            print("[✓] The site uses HTTPS. The connection is secure.")
            
        else:
           print("[!] The site uses HTTP (unencrypted).")
        
        header=response.headers
        if 'X-Content-Type-Options' not in header:
          print("[!] X-Content-Type-Options header is missing.")
          print("Risk: The site may be vulnerable to MIME-sniffing attacks.")
          print("Recommendation: Add 'X-Content-Type-Options: nosniff' to prevent the browser from guessing content types.")
        else:
         print("[✓] X-Frame-Options header is present.")
        if 'Content-Secure-Policy' not in header:
            print("[!] Content-Security-Policy header is missing.")
            print("Risk: The site may be vulnerable to Cross-Site Scripting (XSS) attacks.")
            print(" Recommendation: Implement a strict Content-Security-Policy to whitelist allowed sources.")
        else:
         print("[✓] Content-Security-Policy header is present.")

    except requests.exceptions.RequestException as r:
         print(f"[-] Error connecting to the site: {r}")
    except Exception as e:
        print(f"[-] Error {e}")
    print('*'*50)

# if __name__=="__main__":
#     parser=argparse.ArgumentParser(description='web vulnabrity scanner')
#     parser.add_argument('-t','--target',help='Target URL',required=True)
#     args=parser.parse_args()
#     target_url=args.target
#     scan_vulnabrity(target_url)
