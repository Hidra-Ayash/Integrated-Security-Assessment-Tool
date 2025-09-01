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
            print('The Website will be in dengroius from vulnabrity [MIME]')
        else:
            print(f"The Website Secure from [MIME] and the X-Content-Type-Options exicted")
        if 'Content-Secure-Policy' not in header:
            print('The Website will be in dengroius from Attacks')
        else:
            print(f'The Website Secure and the Content-Secure-Policy exicted')

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
