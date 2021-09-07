import  shodan

SHODAN_API_KEY = "rwzfSinaf2dHAqAqKhsQY3Qd5ufgFEMH"
api = shodan.Shodan(SHODAN_API_KEY)

def get_all_ip(query):
    try:
        res = api.search('homeassistant country:TW')
        print(res)
    except Exception as e:
        print(e)
    pass



if __name__ == '__main__':

    get_all_ip('homeassistant country:TW')
    pass