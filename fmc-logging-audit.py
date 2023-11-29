'''
This script will generate a csv file dump of an access control policy logging settings
In keeping with best practices, deny rules shouls log at the begining of the flow
and allow rules should log at the end of the flow.  the output of this script will
aid in a quick audit of the logging settings per the best practice
'''

# global variable BASE_URL will need to be updated with the url/IP of your FMC

# Developed and tested with the following environment
# OS: windows10
# Python: 3.11.5
# Target platform:  FMC 7.0.4
# Limitations: function getRules uses a limit of 1000. if your ACP contains more than 1000 rules
#               the function will need to be adapted for paging

import requests
from requests.auth import HTTPBasicAuth
import json
import csv
import sys

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

# FMC URL/IP
BASE_URL = 'https://192.168.1.1'


# login to FMC and return the value of auth tokens and domain UUID from the response headers
# exit with an error message if a valid response is not received
def login():
    print('\n\nEnter FMC Credentials')
    user = input("USERNAME: ").strip()
    passwd = input("PASSWORD: ").strip()
    response = requests.post(
       BASE_URL + '/api/fmc_platform/v1/auth/generatetoken',
       auth=HTTPBasicAuth(username=user, password=passwd),
       headers={'content-type': 'application/json'},
       verify=False,
    )
    if response:
        return {'X-auth-access-token': response.headers['X-auth-access-token'], 
        'X-auth-refresh-token':response.headers['X-auth-refresh-token'],
        'DOMAIN_UUID':response.headers['DOMAIN_UUID']}
    else:
        sys.exit('Unable to connect to ' + BASE_URL + ' using supplied credentials')

#retrieve the list of access control policies in FMC
def getPolicies(token, DUUID):
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies',
       headers={'X-auth-access-token':token},
       verify=False,
    )
    raw = response.json()
    return raw

#for a given acess control policy ID, get all the rules using 'expanded' for full detail
#limit is set to 1000.  if your ACP has more than 1000 rules this will need to be update
#to deal with paging
def getRules(token, DUUID, acpID):
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + acpID + '/accessrules?limit=1000&expanded=true',
       headers={'X-auth-access-token':token},
       verify=False,
    )
    raw = response.json()
    return raw


def main():

    #login and retrieve token and DUUID
    result = login()
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')

    #list of dictionaries built from queried/manipulated data, each dict representing a policy rule
    policyRules = []
    #colums to be output to csv, each column matching a dictionary key
    csv_columns = ['name', 'enabled', 'action', 'logBegin', 'logEnd', 'best practice']
   

    #get the list of access control policies in FMC
    policies = getPolicies(token, DUUID)
    
    #prompt for input on which policy to examine
    counter = 0
    print('Policies found')
    for item in policies['items']:
        counter = counter +1
        print('[',counter,']',item['name'])
    entry = int(input('Enter the number of the policy you want to export: '))

    #get the rules associated with the policy
    rules = getRules(token, DUUID, policies['items'][entry -1]['id'])

    #iterate through the rules, extracting the fields/data i care about, and copy them to a new list of dicts
    #FMC 'mostly' does not return keys with empty values so this section will normalize all keys
    for rule in rules['items']:
        new_rule = {}
        new_rule['enabled'] = rule['enabled']
        new_rule['name'] = rule['name']
        new_rule['action'] = rule['action']
        new_rule['logBegin'] = rule['logBegin']
        new_rule['logEnd'] = rule['logEnd']
        if rule['logBegin'] == False and rule['logEnd'] == False:
            new_rule['best practice'] = 'NO'
        elif rule['action'] == 'ALLOW' and rule['logBegin'] == True:
            new_rule['best practice'] = 'NO'
        elif rule['action'] == 'DENY' and rule['logBegin'] == False:
            new_rule['best practice'] = 'NO'
        else:
            new_rule['best practice'] = 'YES'
        policyRules.append(new_rule)
        
        # print('\nnew rule')
        # print(json.dumps(new_rule, indent=2))

    #output to file
    # output = json.dumps(policyRules, indent = 2)  
    #print(output)
    # with open('fmc-acp-output.txt', 'w') as outfile:
    #     outfile.write(output)

    out_file = 'FMC-ACP-' + policies['items'][entry -1]['name'] + '-logging.csv'
    current_section = ''
    current_category = ''
    with open(out_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=csv_columns, extrasaction='ignore')
        writer.writeheader()
        for rule in policyRules:
            writer.writerow(rule)
    print('\nCSV output for access control policy', policies['items'][entry -1]['name'], 'complete')


if __name__ == "__main__":
    main()

