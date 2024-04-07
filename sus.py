import os
import sys
import requests
import argparse
import hashlib

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

VT_API_KEY = ""

VT_API_URL = "https://www.virustotal.com/api/v3/"


class VTScan:
    def __init__(self):
        self.headers = {
            "x-apikey": VT_API_KEY,
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate",
        }

    def upload(self, malware_path):
        print(Colors.BLUE + "Uploading file: " + malware_path + "..." + Colors.ENDC)
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"
        files = {"file": (
            os.path.basename(malware_path),
            open(os.path.abspath(malware_path), "rb"))
        }
        print(Colors.YELLOW + "Upload to " + upload_url + Colors.ENDC)
        res = requests.post(upload_url, headers=self.headers, files=files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print(Colors.YELLOW + self.file_id + Colors.ENDC)
            print(Colors.GREEN + "Successfully uploaded PE file: OK" + Colors.ENDC)
        else:
            print(Colors.RED + "Failed to upload PE file :(" + Colors.ENDC)
            print(Colors.RED + "Status code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

    def analyze(self):
        print(Colors.BLUE + "Getting info about the results of analysis..." + Colors.ENDC)
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                print(Colors.RED + "Malicious: " + str(stats.get("malicious")) + Colors.ENDC)
                print(Colors.YELLOW + "Undetected : " + str(stats.get("undetected")) + Colors.ENDC)
                print()
                for k in results:
                    if results[k].get("category") == "malicious":
                        print("==================================================")
                        print(Colors.GREEN + results[k].get("engine_name") + Colors.ENDC)
                        print("Version : " + results[k].get("engine_version"))
                        print("Category : " + results[k].get("category"))
                        print("Result : " + Colors.RED + results[k].get("result") + Colors.ENDC)
                        print("Method : " + results[k].get("method"))
                        print("Update : " + results[k].get("engine_update"))
                        print("==================================================")
                        print()
                print(Colors.GREEN + "Successfully analyzed: OK" + Colors.ENDC)
                sys.exit()
            elif status == "queued":
                print(Colors.BLUE + "Status QUEUED..." + Colors.ENDC)
                with open(os.path.abspath(self.malware_path), "rb") as malware_file:
                    b = malware_file.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
        else:
            print(Colors.RED + "Failed to get results of analysis :(" + Colors.ENDC)
            print(Colors.RED + "Status code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

    def run(self, malware_path):
        self.upload(malware_path)
        self.analyze()

    def info(self, file_hash):
        print(Colors.BLUE + "Getting file info by ID: " + file_hash + Colors.ENDC)
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                print(Colors.RED + "Malicious: " + str(stats.get("malicious")) + Colors.ENDC)
                print(Colors.YELLOW + "Undetected : " + str(stats.get("undetected")) + Colors.ENDC)
                print()
                for k in results:
                    if results[k].get("category") == "malicious":
                        print("==================================================")
                        print(Colors.GREEN + results[k].get("engine_name") + Colors.ENDC)
                        print("Version : " + results[k].get("engine_version"))
                        print("Category : " + results[k].get("category"))
                        print("Result : " + Colors.RED + results[k].get("result") + Colors.ENDC)
                        print("Method : " + results[k].get("method"))
                        print("Update : " + results[k].get("engine_update"))
                        print("==================================================")
                        print()
                print(Colors.GREEN + "Successfully analyzed: OK" + Colors.ENDC)
                sys.exit()
            else:
                print(Colors.BLUE + "Failed to analyze :(..." + Colors.ENDC)

        else:
            print(Colors.RED + "Failed to get information :(" + Colors.ENDC)
            print(Colors.RED + "Status code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

if __name__ == "__main__":
    print(f'''{Colors.RED} 
 
 █████████  █████  █████  █████████ 
 ███░░░░░███░░███  ░░███  ███░░░░░███
░███    ░░░  ░███   ░███ ░███    ░░░ 
░░█████████  ░███   ░███ ░░█████████ 
 ░░░░░░░░███ ░███   ░███  ░░░░░░░░███
 ███    ░███ ░███   ░███  ███    ░███
░░█████████  ░░████████  ░░█████████ 
 ░░░░░░░░░    ░░░░░░░░    ░░░░░░░░░     

 {Colors.YELLOW}GitHub: hoaxter
 {Colors.YELLOW}MadeBy: Nitin Sikarwar{Colors.ENDC}                                            
          ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mal', required=True, help="PE file path for scanning")
    args = vars(parser.parse_args())
    vtscan = VTScan()
    vtscan.run(args["mal"])
