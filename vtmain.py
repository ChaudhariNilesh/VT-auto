import csv
import os
import time
import requests
import argparse
from datetime import datetime

API_KEY = ""           
NA = "Not Available"

NO_MATCHES_FOUND = "NO MATCHES FOUND"
ERROR = "ERROR" 
CONNECTION_ERROR = "CONNECTION ERROR"


class VirusTotal:
    def __init__(self):
        self.headers = {"accept": "application/json","X-Apikey": API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def upload_hash(self, hash,rescan,verbose):
        if rescan:
            url = self.url + f"files/{hash}/analyse"
            response = requests.post(url, headers=self.headers)
            result = response.json()
            
            rescan_job_url=result['data']['links']['self']
            
            response = requests.get(rescan_job_url, headers=self.headers)
            result = response.json()
            rescan_job_status = result['data']['attributes']['status']
            print("PRE",rescan_job_status)
           
            while rescan_job_status!="completed":
                time.sleep(60)
                print("Wait...")
                response = requests.get(rescan_job_url, headers=self.headers)
                result = response.json()
                rescan_job_status = result['data']['attributes']['status']
                print("POST",rescan_job_status)

       
        url = self.url + f"files/{hash}"
        response = requests.get(url, headers=self.headers)
        result = response.json()
 
         
        if response.status_code == 200 and len(result['data']) > 0:
            try:
                malicious = result['data']['attributes']['last_analysis_stats']['malicious']      
            except:
                malicious = 0
            try:
                meaningful_name = result['data']['attributes']['meaningful_name']       
            except:
                meaningful_name = NA
            try:

                id = result['data']['id']       
            except:
                id = NA
            try:
                names = result['data']['attributes']['names']       
            except:
                names = NA
            try:
                type = result['data']['type']      
            except:
                type = NA
            try:
                type_description = result['data']['attributes']['type_description']      
            except:
                type_description = NA   
           
            try:
                product = result['data']['attributes']['signature_info']['product'] 
            except:
                product = NA
            try:
                file_version = result['data']['attributes']['signature_info']['file version'] 
            except:
                file_version = NA
            try:
                description = result['data']['attributes']['signature_info']['description'] 
            except:
                description = NA
            try:
                orginal_name = result['data']['attributes']['signature_info']['original name'] 
            except:
                orginal_name = NA
            try:
                internal_name = result['data']['attributes']['signature_info']['internal name'] 
            except:
                internal_name = NA
            try:
                verified = result['data']['attributes']['signature_info']['verified'] 
            except:
                verified = NA

            
            try:
                first_seen_in_the_wild = datetime.fromtimestamp( result['data']['attributes']['first_seen_itw_date'])     
            except:
                first_seen_in_the_wild = NA
            try:
                last_analysis_date = datetime.fromtimestamp(result['data']['attributes']['last_analysis_date'])      
            except:
                last_analysis_date = NA
            try:
                first_submission_date = datetime.fromtimestamp(result['data']['attributes']['first_submission_date'])      
            except:
                first_submission_date = NA
            try:
                last_submission_date = datetime.fromtimestamp(result['data']['attributes']['last_submission_date'])       
            except:
                last_submission_date = NA
            try:
                creation_date = datetime.fromtimestamp(result['data']['attributes']['creation_date'])  
            except:
                creation_date = NA
                    
            resultDict={"hash":hash,
                               "malicious":malicious,
                               "id":id,
                               "meaningful_name":meaningful_name,
                               "names":names,
                               "type":type,
                               "type_description":type_description,
                               "product":product,
                               "file_version":file_version,
                               "verified":verified,
                               "description":description,
                               "orginal_name":orginal_name,
                               "internal_name":internal_name,
                               "creation_date":creation_date,
                               "first_seen_in_the_wild":first_seen_in_the_wild,
                               "first_submission_date":first_submission_date,
                               "last_submission_date":last_submission_date,
                               "last_analysis_date":last_analysis_date}

            if verbose:
                self.display(resultDict)

            return resultDict
        
        elif response.status_code == 200 and len(result['data']) < 1:
            print(f"{NO_MATCHES_FOUND : ^90}")
        
        elif response.status_code == 401 and 'error' in result.keys():
            try:
                message = result['error']['message']        
            except:
                message = ERROR
            try:
                code = result['error']['code']      
            except:
                message = ERROR

            print(f"{ERROR : ^90}")

            print(f"{'Message' : <30}" + message)
            print(f"{'Code' : <30}" + code)
        
        else:
            print(f"{ERROR : ^90}")
            print(f"{'Message' : <30}" + CONNECTION_ERROR)


    def run(self, args):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"results_{timestamp}.csv"
        
        if args['file']:
            file = open(args['file'])
            resultListofDict=[]
            for val in file:
                try:
                    resultsDict = virustotal.upload_hash(val,args['rescan'],args['verbose'])
                    resultListofDict.append(resultsDict)
                except:
                    print("API limit, wait...")
                    time.sleep(60)
            
            self.writetocsvfile(file_name,resultListofDict)
            
        if args['hash']:     
            results = virustotal.upload_hash(args['hash'],args['rescan'],args['verbose'])
            self.writetocsvfile(file_name,results)


    def writetocsvfile(self, file_name,resultListofDict):
        with open(file_name, mode='w', newline='') as file:
            fieldnames=["hash","malicious","id","meaningful_name","names","type","type_description","product","file_version","description","verified","orginal_name","internal_name","creation_date",\
                    "first_seen_in_the_wild","first_submission_date","last_submission_date","last_analysis_date"]
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for row in resultListofDict:
                writer.writerow(row)
    
    def display(self,resultDict):
            
            print(f"{'Malicious' : <30}" + str(resultDict['malicious']))
            print("\n")
            print(f"{'ID' : <30}" + resultDict['id'])
            print(f"{'Name' : <30}" + resultDict['meaningful_name'])
            print(f"{'Other Names' : <30}", "".join(resultDict['names']))
            print(f"{'Type' : <30}" + resultDict['type'])
            print(f"{'Type Description' : <30}" + resultDict['type_description'])
            print(f"{'Product' : <30}" + resultDict['product'])
            print(f"{'File Version' : <30}" + resultDict['file_version'])
            print(f"{'Description' : <30}" + resultDict['description'])
            print(f"{'Verified' : <30}" + resultDict['verified'])
            print(f"{'Orignal Name' : <30}" + resultDict['orginal_name'])
            print(f"{'Internal Name' : <30}" + resultDict['internal_name'])

            print("\n")

            print(f"{'Creation Time' : <30}" + str(resultDict['creation_date']))
            print(f"{'First Seen In The Wild' : <30}" + str(resultDict['first_seen_in_the_wild']))
            print(f"{'First Submission Date' : <30}" + str(resultDict['first_submission_date']))
            print(f"{'Last Submission Date' : <30}" + str(resultDict['last_submission_date']))
            print(f"{'Last Analysis Date' : <30}" + str(resultDict['last_analysis_date']))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--hash')
    parser.add_argument('--file')
    parser.add_argument('--rescan', default=False, action="store_true")
    parser.add_argument("--verbose", default=False, action="store_true")
    args = vars(parser.parse_args())
    virustotal = VirusTotal()
    virustotal.run(args)