import json
import os
import re
import pandas as pd
from OTXv2 import OTXv2, IndicatorTypes 
from pandas.io.json import json_normalize
from datetime import datetime, timedelta


import requests


headers={"X-OTX-API-KEY": ""}

# res =  requests.get("https://otx.alienvault.com/api/v1/search/pulses?sort=modified&limit=50&modified_since=2022-10-14T16:48:28",headers=headers)
# res =  requests.get("https://otx.alienvault.com/api/v1/search/users",headers=headers)
# res =  requests.get("https://otx.alienvault.com/api/v1/search/pulses?sort=-created",headers=headers)

# res =  requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since=2022-10-14T16:48:28",headers=headers)
# res =  requests.get("https://otx.alienvault.com/api/v1/pulses/652a3e29e7c2c2522258add6",headers=headers)



def subscribeusers():
    usersdata = pd.read_csv("otx_user.csv")
    usersdata = usersdata['username'].tolist()
    for username in usersdata[1528:]:
        
        otx_users =  requests.get(f"https://otx.alienvault.com/api/v1/users/{username}/subscribe",headers=headers)
        print(username," at ",usersdata.index(username),'--',otx_users.json())

def getpulses():
    current_date = datetime.now()
    one_year_ago = current_date - timedelta(days=365)
    one_year_ago_iso = one_year_ago.strftime("%Y-%m-%dT%H:%M:%S")

    pulse_resp =  requests.get(f"https://otx.alienvault.com/api/v1/pulses/subscribed?sort=-created&limit=50&modified_since={one_year_ago_iso}&page=118",headers=headers)

    pulse_resp = pulse_resp.json()

    



    idfirstpulse=pulse_resp['results'][0]['id']
    datefirstpulse=pulse_resp['results'][0]['created']

    idlastpulse=pulse_resp['results'][-1]['id']
    datelastpulse=pulse_resp['results'][-1]['created']
    
    PULSE_FILENAME=f"otx_pulses_{idfirstpulse}-{datefirstpulse}_{idlastpulse}-{datelastpulse}.json".replace(":","")

    
    with open(PULSE_FILENAME, 'w') as f:
        json.dump(pulse_resp, f)

    print(idfirstpulse, datefirstpulse, idlastpulse, datelastpulse,'next:',pulse_resp['next'])


    while 'next' in pulse_resp:
        next_pulse_link = pulse_resp['next']

        if next_pulse_link is not None:
            pulse_resp = requests.get(next_pulse_link,headers=headers)
            req_statuscode = pulse_resp.status_code
           
            while req_statuscode != 200:
                with open("failedpulses.txt","a+") as failfile:
                    failfile.write(f"\n{pulse_resp.status_code} : {next_pulse_link}")
                    print("FAILED",next_pulse_link)
                    match = re.search(r'page=(\d+)', next_pulse_link)
                
                    if match:
                        page_value = int(match.group(1))
                        incremented_page = page_value + 1
                
                    next_pulse_link = re.sub(r'&page=(\d+)$', str(incremented_page), str(next_pulse_link))

                    pulse_resp = requests.get(next_pulse_link,headers=headers)
                    req_statuscode = pulse_resp.status_code
    


            pulse_resp = pulse_resp.json()
        
            idfirstpulse=pulse_resp['results'][0]['id']
            datefirstpulse=pulse_resp['results'][0]['created']

            idlastpulse=pulse_resp['results'][-1]['id']
            datelastpulse=pulse_resp['results'][-1]['created']

            PULSE_FILENAME=f"otx_pulses_{idfirstpulse}-{datefirstpulse}_{idlastpulse}-{datelastpulse}.json".replace(":","")

            with open(PULSE_FILENAME, 'w') as f:
                    json.dump(pulse_resp, f)
            
            print(idfirstpulse, datefirstpulse, idlastpulse, datelastpulse,'next:',pulse_resp['next'])

        else:
            print(f'The pulses csv saved!')
            break







def getotxusers():

    otx_users =  requests.get("https://otx.alienvault.com/otxapi/users?sort=-pulse_count&limit=20&page=101",headers=headers)
    otx_users = otx_users.json()
    
    otx_users_dict = otx_users['results']


    otx_usersdf = pd.DataFrame.from_dict(otx_users_dict)
    otx_usersdf = otx_usersdf.drop(columns=["awards","award_count","avatar_url",'accepted_edits_count'])
    isFirst=False

    if not os.path.isfile("otx_user.csv"):
        otx_usersdf.to_csv(f'otx_user.csv', index = False, header=True)
        del otx_usersdf
        isFirst=True

    print(otx_users['results'][-1]['username']," - ",len(otx_users['results']),'next:',otx_users['next'])

    while 'next' in otx_users:
        next_users_link = otx_users['next']

        if next_users_link is not None:

            otx_users = requests.get(next_users_link,headers=headers)
            otx_users = otx_users.json()

            print(otx_users['results'][-1]['username']," - ",len(otx_users['results']),'next:',next_users_link)

    
            otx_users_dict = otx_users['results']
            next_usersdf = pd.DataFrame.from_dict(otx_users_dict)

            if isFirst:
                otx_usersdf = next_usersdf.drop(columns=["awards","award_count","avatar_url",'accepted_edits_count'])
                print(f'The shape of the user df is {otx_usersdf.shape[0]}')
                isFirst=False
        
            else:
                next_usersdf = next_usersdf.drop(columns=["awards","award_count","avatar_url",'accepted_edits_count'])
                otx_usersdf = pd.concat([otx_usersdf, next_usersdf], ignore_index=True, sort=False)
                print(f'The shape of the user df is {otx_usersdf.shape[0]}')
                otx_usersdf.to_csv('otx_user.csv',  mode='a', index=False, header=False)
            
            del next_usersdf

        else:
            print(f'The total shape of all users from otx is {otx_usersdf.shape[0]}')
            print(f'The users csv saved!')
            break



if __name__ == "__main__":
    getpulses()

# df = pd.DataFrame.from_dict(data['results'])
# df = df.drop(columns=["awards","award_count","avatar_url",'accepted_edits_count'])
# df.to_csv (f'user.csv', index = False, header=True)


