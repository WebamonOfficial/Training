import json
import re
import ipaddress
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth
import time 

def identify_string(input_string):
    # Check if it is a valid domain
    def is_domain(input_string):
        domain_pattern = re.compile(
            r'^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$'
        )
        return bool(re.match(domain_pattern, input_string))

    # Check if it is a valid URL
    def is_url(input_string):
        try:
            result = urlparse(input_string)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    # Check if it is a valid IP address
    def is_ip_address(input_string):
        try:
            ipaddress.ip_address(input_string)
            return True
        except ValueError:
            return False

    # Check if it is a valid MD5 hash
    def is_md5_hash(input_string):
        md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
        return bool(re.match(md5_pattern, input_string))

    # Check if it is a valid SHA1 hash
    def is_sha1_hash(input_string):
        sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        return bool(re.match(sha1_pattern, input_string))

    # Check if it is a valid SHA256 hash
    def is_sha256_hash(input_string):
        sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
        return bool(re.match(sha256_pattern, input_string))

    if is_domain(input_string):
        return 'Domain'
    elif is_url(input_string):
        return 'URL'
    elif is_ip_address(input_string):
        return 'IP'
    elif is_md5_hash(input_string):
        return 'MD5'
    elif is_sha1_hash(input_string):
        return 'SHA1'
    elif is_sha256_hash(input_string):
        return 'SHA256'
    else:
        return 'Unknown'




#TODO Create free censys apikey pair
def censysIP(ip):
    reply = requests.get(f'https://search.censys.io/api/v2/hosts/{ip}', auth=HTTPBasicAuth('key', 'secret')).json()
    print(json.dumps(reply, indent=4))



#public hash lookup
def hashCircle(hash, type):
    if type == 'MD5':
        reply = requests.get(f'https://hashlookup.circl.lu/lookup/md5/{hash}').json()
        return reply
    elif type == 'SHA1':
        reply = requests.get(f'https://hashlookup.circl.lu/lookup/sha1/{hash}').json()
        return reply
    elif type == 'SHA256':
        reply = requests.get(f'https://hashlookup.circl.lu/lookup/sha256/{hash}').json()
        return reply
    else:
        return False

#TODO Create free urlscan apikey

def urlScan(urlDomain):
    headers = {'API-Key': 'key', 'Content-Type': 'application/json'}
    data = {"url": urlDomain, "visibility": "public"}
    responseAPI = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    response = requests.get(responseAPI.json()['api'])
    while response.status_code != 200:
        time.sleep(1.5)
        response = requests.get(responseAPI.json()['api'])
    print(json.dumps(response.json(),indent=4))


#TODO Create free binaryedge apikey

def binaryEdge(domain):
    headers = {'X-Key' : 'key'}
    dns = requests.get(f'https://api.binaryedge.io/v2/query/domains/subdomain/{domain}', headers=headers).json()
    print(f'Subdomains for {domain}')
    print(json.dumps(dns['events'],indent=4))







def main():
    ioc = input('Enter IOC: ').strip()
    iocType = identify_string(ioc)
    if iocType == 'IP':
        censysIP(ioc)
    elif iocType in ['MD5','SHA1','SHA256']:
        print(f'Hashcircle reply for {ioc}({iocType})')
        print(json.dumps(hashCircle(ioc,iocType),indent=4))
    elif iocType == 'Domain':
        binaryEdge(ioc)
        urlScan(f'http://{ioc}')
    elif iocType == 'URL':
        urlScan(ioc)
    else:
        return False


if __name__ == '__main__':
    main()



