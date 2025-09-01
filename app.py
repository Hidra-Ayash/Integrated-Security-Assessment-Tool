import analys_tool_dev as an
import port_scan as po
import web_vulnabrity_scanner as we
import sys
def main_menu():
    while True:
        print("\n" + "=" * 50)
        print("Security Toolkit Main Menu".center(50))
        print("=" * 50)
        print("1. Port Scanner")
        print("2. Web Vulnerability Scanner")
        print("3. Log Analyzer")
        print("4. Exit")
        inp=input("Please select an option (1-4): ")
        if inp=='1':
            host=input("Please Enter The Host Name You Need To Scan e.g(example.com) : ")
            start=int(input("Enter Starting Port :  "))
            end=int(input("Enter Ending Port : "))
            po.port_scan(host,start,end)
        elif inp=='2':
            url=input("Please Enter The URL You Need To Check e.g(https://example.com) : ")
            we.scan_vulnabrity(url)
        elif inp=='3':
            filePath=input('Please Enter The Path of File e.g(example.log) : ')
            an.analyse_file(filePath)
        else:
            sys.exit()

if __name__=="__main__":
    main_menu()    

            
            