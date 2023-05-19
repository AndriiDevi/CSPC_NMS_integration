import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


user = "provide API user name here"
pwd = "provide password here"
authentication_id = "Tacacs"
body = {
"username": user,
"password": pwd,
"authentication_id": authentication_id
}

full = 'https://netbrain.novartis.net/ServicesAPI/API/V1/Session'

# Set proper headers
headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

try:
    # Do the HTTP request
    response = requests.post(full, headers=headers, data=json.dumps(body), verify=False)
    # Check for HTTP codes other than 200
    print(f"initial call status code: {response.status_code}")
    if response.status_code == 200:
        # Decode the JSON response into a dictionary and use the data
        js = response.json()
        print(js)
    else:
        print("Get token failed! - " + str(response.text))
except Exception as e:
    print(str(e))
headers["Token"] = js.get('token')
print(headers)
full_url = 'https://netbrain.novartis.net/ServicesAPI/API/V1/CMDB/Devices/GroupDevices'
data = {
"path": "Policy Device Groups/CSPC_PDG" # specify group which you would like to call
}
# Set proper headers
#headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
try:
    # Do the HTTP request
    response = requests.get(full_url, params=data, headers=headers, verify=False)
    # Check for HTTP codes other than 200
    if response.status_code == 200:
        # Decode the JSON response into a dictionary and use the data
        result = response.json()
        print(result)
    else:
        print("Get devices from a device group failed- " + str(response.text))

except Exception as e:
    print(str(e))
