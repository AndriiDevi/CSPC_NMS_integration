import requests
import getpass
import time
import logging
import json
import csv
import os
import subprocess
import urllib3


class SolarWindsAPI:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.token = server_config.get('token')
        self.ip = server_config.get('server_ip')
        self.connectivity = False
        self.max_limit = 50
        self.port = 17778
        self.username = server_config.get('server_u')
        self.password = server_config.get('server_p')
        self.base_url = f'https://{self.ip}:{self.port}/SolarWinds/InformationService/v3/Json/Query'

    def get_all_node_ips(self):
        params = {"query": "SELECT IPAddress, Status, Vendor FROM Orion.Nodes WHERE Vendor='Cisco'",
                  "pageSize": 1000,
                  "page": 1
                  }
        ip2hostname = []
        devices = []
        while True:
            response = requests.get(self.base_url, params=params, auth=(self.username, self.password), verify=False)
            data = response.json()
            devices += data['results']
            if len(data['results']) < params['pageSize']:
                break

            params['page'] += 1
        for device in devices:
            if device.get('status') == 2:
                logging.error(f"device: {device.get('IPAddress')} is not reachable, excluding from seed")
            else:
                ip2hostname.append({'ip': device.get('IPAddress'), 'hostname': device.get('IPAddress')})

        return ip2hostname

    def check_connectivity(self):
        """Make one API call to device api and return self.connectivity = True if successfull"""
        params = {
            'query': 'SELECT TOP 1 EngineID,EngineVersion FROM Orion.Engines ORDER BY EngineID'
        }
        try:
            response = requests.get(self.base_url, params=params, auth=(self.username, self.password), verify=False,
                                    timeout=10)
            if response.status_code == 200:
                print("--------------------------------------------------------------------------------------------")
                print(
                    f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
                print("--------------------------------------------------------------------------------------------")
                self.connectivity = True
                print(f'your SolaWinds version below: /n{response.json()}')
            else:
                print(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
        except Exception as e:
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')


class IseApi:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.token = server_config.get('token')
        self.ip = server_config.get('server_ip')
        self.connectivity = False
        self.verify = False
        self.max_limit = 100
        self.port = 9060
        self.username = server_config.get('server_u')
        self.password = server_config.get('server_p')
        self.auth = (self.username, self.password)
        self.url = f'https://{self.ip}:{self.port}'
        if not self.verify:
            import urllib3
            urllib3.disable_warnings()


    def check_connectivity(self):
        s = requests.Session()
        s.auth = self.auth
        s.headers.update({'accept': "application/json", 'cache-control': "no-cache"})

        # Check connectivity by making a test request to a known reliable URL
        try:
            response = s.get(f'{self.url}/ers/config/networkdevice?size=100', verify=self.verify, timeout=10)  # Use a reliable URL
            response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code
            print("--------------------------------------------------------------------------------------------")
            print(
                f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            self.connectivity = True
        except requests.exceptions.RequestException as e:
            self.connectivity = False
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')
            # Handle the connectivity issue as needed (e.g., log the error)

        return s
    def _session(self):
        s = requests.Session()
        s.auth = self.auth
        s.headers.update({'accept': "application/json", 'cache-control': "no-cache"})
        return s

    def _get(self, s, url):
        print(f"Fetching URL: {url}")  # Replace logging with a simple print statement
        res = s.get(url, verify=self.verify)  # Use self.verify directly
        if res.status_code != 200:
            print(f"Failed to fetch data: {res.status_code}")
            raise RuntimeError(f"Failed to fetch data: {res.status_code}")
        jsondata = json.loads(res.text)
        return jsondata

    def get_all_network_elements(self):
        all_devices = self.network_device_get_all()
        print(all_devices)
        print('===================================================================')
        s = self._session()
        ip2hostname = []

        # Extract IP addresses and hostnames from all devices
        for resource in all_devices['SearchResult']['resources']:
            jsondata = self._get(s, resource['link']['href'])
            #print(jsondata)

            # Extract the IP address and hostname from each NetworkDevice
            #device = jsondata['NetworkDevice']
            #print(device)
            ip_address = device.get('NetworkDeviceIPList', [{}])[0].get('ipaddress', '')
            hostname = device.get('name', '')

            # Append the IP and hostname to ip2hostname list
            print(f'appending: {ip_address}, hostname: {hostname}')
            ip2hostname.append({"ip": ip_address, "hostname": hostname})
        s.close()
        return ip2hostname

    def network_device_get_all(self):
        path = '/ers/config/networkdevice'
        s = self._session()
        full_url = f'{self.url}{path}?size={self.max_limit}&filter=type.CONTAINS.cisco' # filtering cisco devices here
        jsondata = self._get(s, full_url)
        all_devices = jsondata
        while True:
            if 'nextPage' in jsondata['SearchResult']:
                full_url = jsondata['SearchResult']['nextPage']['href']
                jsondata = self._get(s, full_url)
                all_devices['SearchResult']['resources'] += jsondata['SearchResult']['resources']
            else:
                break
        s.close()
        return all_devices
class CdoAPI:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.token = server_config.get('token')
        self.ip = server_config.get('server_ip')
        self.port = server_config.get('port', '443')
        self.headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {self.token}'}
        self.url_all_devices = f'https://{self.ip}/aegis/rest/v1/services/targets/devices'
        self.connectivity = False
        self.max_limit = 50
        self.params = {
            'offset': '0',
            'limit': '50',
            # 'q': '(model:false)',
            'resolve': '[targets/devices.{name,ipv4,state,DeviceConnectivityState,connectivityState,connectivityError}]'
        }

    def check_connectivity(self):
        """Make one API call to device api and return self.connectivity = True if successfull"""
        print(self.url_all_devices)
        try:
            response = requests.get(self.url_all_devices, params=self.params, headers=self.headers, timeout=10)
            if response.status_code == 200:
                print("--------------------------------------------------------------------------------------------")
                print(
                    f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
                print("--------------------------------------------------------------------------------------------")
                self.connectivity = True
            else:
                print(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
        except Exception as e:
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')

    def get_all_devices(self):
        all_devices = []  # List to store all devices

        offset = 0

        while True:
            self.params['offset'] = str(offset)
            response = requests.get(self.url_all_devices, params=self.params, headers=self.headers)
            devices = response.json()
            # print(devices)
            if response.status_code != 200:
                print(
                    f"Unable to connect to {self.server_type} server: {self.ip} Response status code {response.status_code}")
                logging.error(
                    f"Unable to connect to {self.server_type} server: {self.ip} Response status code {response.status_code}")
                break
            # Check if devices is empty
            if not devices:
                break

            all_devices.extend(devices)

            # Increment offset for the next page
            offset += self.max_limit

        # Process all_devices list and extract name and ip
        ip2hostname = []
        for device in all_devices:
            print(device)
            name = device.get('name')
            ipv4 = device.get('ipv4')
            if name and ipv4:
                if ':' in ipv4:
                    ip = ipv4.split(':')[0].strip()  # Extract IP address without port
                else:
                    ip = ipv4.strip()  # Use the IP address as is
                ip2hostname.append({'ip': ip, 'hostname': name})
            elif name:
                ip2hostname.append({'ip': name, 'hostname': name})
                logging.info(f"no ip found for device {name}")

            elif ipv4:
                if ':' in ipv4:
                    ip = ipv4.split(':')[0].strip()  # Extract IP address without port
                else:
                    ip = ipv4.strip()  # Use the IP address as is
                ip2hostname.append({'ip': ip, 'hostname': ip})
                logging.info(f"No hostname found for device {name}")
            else:
                logging.error(f"device response below does not contain IP and hostname info {device}")
        # Return the result list
        return ip2hostname


class NetbrainAPI:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.authentication_id = server_config.get('authentication_id', '')
        self.ip = server_config.get('server_ip')
        self.group = server_config.get('group', '')
        self.port = server_config.get('port', '8000')
        self.headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        self.url_all_devices1 = f'https://{self.ip}/ServicesAPI/API/V1/CMDB/Devices/GroupDevices'
        self.url_all_devices = f'https://{self.ip}/ServicesAPI/API/V1/CMDB/Devices?vendor=Cisco'
        self.url_initial_session = f'https://{self.ip}/ServicesAPI/API/V1/Session'
        self.connectivity = False
        self.max_limit = 50
        self.username = server_config.get('server_u')
        self.password = server_config.get('server_p')
        self.body = {"username": self.username, "password": self.password, "authentication_id": self.authentication_id}

    def check_connectivity(self):
        print(self.url_all_devices)
        print(self.username)
        try:
            response = requests.post(self.url_initial_session, data=json.dumps(self.body), headers=self.headers,
                                     timeout=10, verify=False)
            if response.status_code == 200:
                print("--------------------------------------------------------------------------------------------")
                print(
                    f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
                print("--------------------------------------------------------------------------------------------")
                self.connectivity = True
            else:
                print(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
                print(response.text)
        except Exception as e:
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')

    def get_token(self):
        try:
            response = requests.post(self.url_initial_session, data=json.dumps(self.body), headers=self.headers,
                                     timeout=10, verify=False)
            if response.status_code == 200:
                print("--------------------------------------------------------------------------------------------")
                print(
                    f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
                print("--------------------------------------------------------------------------------------------")
                auth_token = response.json().get('token')
                self.headers['Token'] = auth_token
            else:
                print(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
                logging.error(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
        except Exception as e:
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')
            logging.error(
                f"unable to create token for {self.server_type} server {self.ip} , error: {response.status_code} for url: {response.url}")

    def get_all_devices(self):
        print(f"Fetching all devices with vendor=Cisco")
    
        devices = []  # List to store all devices
        ip2hostname = []  # List to store IP-to-hostname mappings
        url = f"{self.url_all_devices}?vendor=Cisco"  # Base URL with vendor filter
    
        try:
            while url:
                print(f"Fetching devices from URL: {url}")
                logging.info(f"Fetching devices from {self.server_type} server at {self.ip}, URL: {url}")

                # Make the API request
                response = requests.get(url, headers=self.headers, verify=False)

                if response.status_code == 200:
                    result = response.json()

                    # Add devices from the current page to the main list
                    devices_result = result.get("devices", [])
                    devices.extend(devices_result)
                
                    # Get the URL for the next page
                    url = result.get("next")  # If 'next' is null, the loop will terminate
                
                    print(f"Devices fetched: {len(devices_result)}, Next URL: {url}")
                    logging.info(f"Devices fetched: {len(devices_result)} from {self.server_type} server {self.ip}")
                else:
                    print(f"Get Devices API failed. URL: {response.url}, Error: {response.status_code}")
                    logging.error(f"Get Devices API failed. URL: {response.url}, Error: {response.status_code}")
                    break

            # Convert devices into IP-to-hostname mappings
            for device in devices:
                ip_address = device.get('mgmtIP')
                hostname = device.get("hostname")
                if ip_address:
                    ip2hostname.append({"ip": ip_address, "hostname": hostname})

            print(f"Total devices retrieved: {len(devices)}")
            logging.info(f"Total devices retrieved for {self.server_type} server {self.ip}: {len(devices)}")
            return ip2hostname

        except Exception as e:
            logging.error(f"Unable to fetch devices from {self.server_type} server {self.ip}. Error: {str(e)}")
            print(f"Error fetching devices: {e}")
            return []
    def get_all_devices1(self):
        print(self.group)
        filter1 = {'vendor': 'Cisco'}
        devices = []
        ip2hostname = []
        skip = 0
        count = self.max_limit
        try:
            while count == 50:
                payload = {
                    # "version": 1,
                    "path": self.group,
                    "skip": skip,
                    # "fullattr": 0,
                    # "filter": json.dumps(filter1)

                }
                response = requests.get(self.url_all_devices, params=payload, headers=self.headers, verify=False)
                if response.status_code == 200:
                    result = response.json()
                    print(result)
                    count = len(result["devices"])
                    skip = skip + count
                    devices_result = result["devices"]
                    for dev in devices_result:
                        devices.append(dev)
                    # print(result)
                else:
                    print(f"Get Devices API url: {response.url} -  failed with error: {response.status_code}")

            for device in devices:
                ip2hostname.append({"ip": device.get('mgmtIP'), "hostname": device.get("hostname")})
            print(f'all device count: {len(devices)}')
            logging.info(f'device count for {self.server_type} server {self.ip}: {len(devices)}')
            return ip2hostname
        except Exception as e:
            logging.error(f"unable to get all devices API for url: {response.url} with error: {e}")


class NetboxAPI:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.token = server_config.get('token')
        self.ip = server_config.get('server_ip')
        self.port = server_config.get('port', '8000')
        self.headers = {'Content-Type': 'application/json',
                        'Authorization': f'Token {self.token}'}
        self.connectivity = False
        self.max_limit = 49
        self.url_all_devices = f'https://{self.ip}/api/dcim/devices/?limit={self.max_limit}&manufacturer=cisco&status=active&'


    def check_connectivity(self):
        print(self.url_all_devices)
        try:
            response = requests.get(self.url_all_devices, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200:
                print("--------------------------------------------------------------------------------------------")
                print(
                    f" Connection to {self.server_type} server: {self.ip} was SUCCESSFUL. Added server to the configuration ")
                print("--------------------------------------------------------------------------------------------")
                self.connectivity = True
            else:
                print(
                    f"!!!Warning!!!, I was not able to connect to {self.server_type} server {self.ip} , error: {response.status_code}, please check credentials or user role")
        except Exception as e:
            print(f'Unable to connect to  {self.server_type} server {self.ip}, please check firewall/proxy\nerror: {e}')

    def get_all_devices(self):
        payload = {
            "manufacturer": "cisco",
            "has_primary_ip": True,
            "status": "active"
        }
        devices = []
        ip2hostname = []
        url = self.url_all_devices
        while url:
            print(f'url: {url}')
            response = requests.get(url, json=payload, headers=self.headers, verify=False)
            if response.status_code == 200:
                data = response.json()

                devices += data['results']

                url = data['next']  # get the next page URL, if any
            else:
                print(f'Error getting devices: {response.status_code}')
                return None
        print(f'all device count: {len(devices)}')
        for device in devices:
            primary_ip4 = device.get('primary_ip4')
            if primary_ip4 and primary_ip4.get('address'):
                address = primary_ip4.get('address').split('/')[0]
                hostname = device.get("name") or address  # Use IP as hostname if name is missing
                ip2hostname.append({"ip": address, "hostname": hostname})

        return ip2hostname


class SDwanApi:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.connectivity = False
        self.username = server_config.get('server_u')
        self.password = server_config.get('server_p')
        self.ip = server_config.get('server_ip')
        self.port = server_config.get('port', '443')
        self.base_url = f"https://{self.ip}:{self.port}"
        self.authendpoint = "/j_security_check"
        self.tokenendpoint = "/dataservice/client/token"

    def check_connectivity(self):
        url = self.base_url + self.authendpoint
        payload = {'j_username': self.username, 'j_password': self.password}

        response = requests.post(url=url, data=payload, verify=False)
        if response.ok:
            try:
                cookies = response.headers["Set-Cookie"]
                jsessionid = cookies.split(";")
                self.connectivity = True
            except:
                logging.error("No valid JSESSION ID returned")
                print("No valid JSESSION ID returned\n")
        else:
            print(f"connection to {self.ip} got failed with en error: {response.status_code}")

    def get_jsessionid(self):
        url = self.base_url + self.authendpoint
        payload = {'j_username': self.username, 'j_password': self.password}

        response = requests.post(url=url, data=payload, verify=False)
        if response.ok:
            try:
                cookies = response.headers["Set-Cookie"]
                jsessionid = cookies.split(";")
                self.jsessionid = jsessionid[0]
            except:
                logging.error("No valid JSESSION ID returned")
                print("No valid JSESSION ID returned\n")
        else:

            print(f"connection to {self.ip} got failed with en error: {response.status_code}")
            logging.error(f"connection to {self.ip} got failed with en error: {response.status_code}")

    def get_token(self):
        headers = {'Cookie': self.jsessionid}
        url = self.base_url + self.tokenendpoint
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            self.token = response.text

        else:
            print(f"unable to issue token: {response.status_code}")
            logging.error(f"unable to issue token: {response.status_code}")
            logging.error(f"connection to {self.ip} got failed with en error: {response.status_code}")

    def collect_ips_sd_wan(self):
        """this function will check all devices and return dictionary with {"ip":"value","hostname":"value"}"""
        print(f"retrieving data from {self.server_type} server: {self.ip}")
        ip2hostname = []

        if self.token is not None:
            header = {'Content-Type': "application/json", 'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
            result = requests.get(url=f"https://{self.ip}/dataservice/device", headers=header, verify=False)
            if result.ok:
                device_list = result.json().get("data")
                for device in device_list:
                    if device.get("reachability") != "reachable":
                        logging.error(f"device: {device.get('system-ip')} is not reachable")
                    elif device.get('system-ip'):
                        ip2hostname.append(
                            {"ip": device.get('system-ip'),
                             "hostname": device.get("host-name", device.get('system-ip'))})
                return ip2hostname
            else:
                logging.error(f"devices API call got failed with en error {result.status_code}")
                return None
        else:
            print(f"not able to login to {self.server_type}: {self.ip}")
            return None


def collect_ips_dnac1(server_info):
    """This function retrieves all devices and returns a dictionary with {"ip":"value","hostname":"value"}"""
    print(f"Retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    ip2hostname = []

    # Authenticate and obtain the token
    response = requests.post(f"https://{server_info.get('server_ip')}/dna/system/api/v1/auth/token",
                             auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
    try:
        token = response.json()['Token']
        headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}

        pagination = 0
        url = f"https://{server_info.get('server_ip')}/dna/intent/api/v1/network-device"
        devices_request = requests.get(url, headers=headers, verify=False)
        initial_devices = devices_request.get('response', [])
        for device in initial_devices:
            if device.get('reachabilityStatus') != 'Reachable':
                logging.error(f"Device: {device.get('managementIpAddress')} is not reachable")
            elif device.get('managementIpAddress'):
                ip2hostname.append({"ip": device.get('managementIpAddress'),
                                    "hostname": device.get('hostname', device.get('managementIpAddress'))})
        while True:
            pagination += 500
            print(f"pagination {pagination}")
            url = f"https://{server_info.get('server_ip')}/dna/intent/api/v1/network-device"
            url = url + f"/{pagination}/500"

            devices_request = requests.get(url, headers=headers, verify=False)
            print(url)
            print(len(devices_request.json().get('response')))

            if len(devices_request.json().get('response')) == 0:
                print("device count is 0")
                break

            response_json = devices_request.json()
            devices = response_json.get('response', [])

            # Process devices from the current page
            for device in devices:
                if device.get('reachabilityStatus') != 'Reachable':
                    logging.error(f"Device: {device.get('managementIpAddress')} is not reachable")
                elif device.get('managementIpAddress'):
                    ip2hostname.append({"ip": device.get('managementIpAddress'),
                                        "hostname": device.get('hostname', device.get('managementIpAddress'))})

        return ip2hostname
    except Exception as e:
        print(f'Failed to collect devices from DNAC with an error: {e}')
        logging.error(f'Failed to collect devices from DNAC with an error: {e}')
        return ip2hostname


def collect_ips_dnac(server_info):
    """This function retrieves all devices and returns a dictionary with {"ip":"value","hostname":"value"}"""
    print(f"Retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    ip2hostname = []

    # Authenticate and obtain the token
    response = requests.post(f"https://{server_info.get('server_ip')}/dna/system/api/v1/auth/token",
                             auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
    print(response.url)
    try:
        all_devices = []
        token = response.json()['Token']
        print(f"token: {token}")
        headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
        url = f"https://{server_info.get('server_ip')}/dna/intent/api/v1/network-device"

        start_index = 1
        records_to_return = 500
        while True:
            # Construct the URL with the current pagination parameters
            current_url = f"{url}/{start_index}/{records_to_return}"
            # Send the request
            print(current_url)
            dev_response = requests.get(current_url, headers=headers, verify=False)
            response_json = dev_response.json()
            devices = response_json.get('response', [])
            print(devices)
            # If no devices are returned, break out of the loop
            if len(devices) == 0:
                break
            # Add the devices from the current page to the list
            all_devices.extend(devices)
            # Increment the start index for the next page
            start_index += records_to_return
            print(f"incrementing index: {start_index}")
        # all_devices_filtered = [device for device in all_devices if
        #                        "access point" not in device.get('type', '').lower()]
        # all_devices_filtered = [device for device in all_devices if
        #                        device and "access point" not in device.get('type', '').lower()]
        all_devices_filtered = [device for device in all_devices if
                                device.get('type') and "access point" not in device.get('type', '').lower()]
        print(f"filtered device count {len(all_devices_filtered)}")
        for device in all_devices_filtered:
            if device.get('reachabilityStatus') != 'Reachable':
                logging.error(f"Device: {device.get('managementIpAddress')} is not reachable")
            elif device.get('managementIpAddress'):
                ip2hostname.append({"ip": device.get('managementIpAddress'),
                                    "hostname": device.get('hostname', device.get('managementIpAddress'))})
        return ip2hostname
    except Exception as e:
        print(f'error occured: {e}')
        logging.error(f'Failed to collect devices from DNAC with an error: {e}')
        return ip2hostname


def collect_ips_epnm(server_info):
    """this function will check all devices and return dictionary with {"ip":"value","hostname":"value"}"""
    print(f"retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    url = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/InventoryDetails.json"
    r = requests.get(url, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
    if r.ok:
        device_count = int(r.json().get('queryResponse').get('@count'))
        # print(f"Device count: {device_count}")
        r2 = requests.get(url=f"https://{server_info.get('server_ip')}/webacs/api/v4/op/rateService/rateLimits.json",
                          auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
        print(f"query limit: {r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']}")
        query_limit = r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']
        logging.info(
            f"query limit: {r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']} for server: {server_info.get('server_ip')}")
        startpull = 0
        ip2hostname = []
        list_of_ips = []
        while startpull < device_count:
            print(f"========= Polling device IPs from: {startpull} to: {startpull + query_limit} ==========")
            devices_ip = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/Devices.json?.full=true&.maxResults={query_limit}&.firstResult={startpull}"
            r3 = requests.get(devices_ip, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
            data = r3.json().get('queryResponse').get('entity')
            try:
                for i in data:
                    if i.get('devicesDTO').get('reachability') != 'REACHABLE':
                        logging.error(f"devices: {i.get('devicesDTO').get('ipAddress')} is not reachable")
                    elif i.get('devicesDTO').get('deviceType') == 'Unsupported Cisco Device':
                        logging.error(f"devices: {i.get('devicesDTO').get('ipAddress')} is not supported")
                    elif i.get('devicesDTO').get('ipAddress') and i.get('devicesDTO').get('deviceName'):
                        ip2hostname.append(
                            {"ip": i['devicesDTO']['ipAddress'], "hostname": i['devicesDTO']['deviceName']})
                        list_of_ips.append(i['devicesDTO']['ipAddress'])
                    elif i.get('devicesDTO').get('ipAddress') and not i.get('devicesDTO').get('deviceName'):
                        logging.error(
                            f"device {i.get('devicesDTO').get('ipAddress')} has no hostname in API hence setting up ip as hostname, function collect_ips()")
                        ip2hostname.append(
                            {"ip": i['devicesDTO']['ipAddress'], "hostname": i['devicesDTO']['ipAddress']})
                        list_of_ips.append(i['devicesDTO']['ipAddress'])
                    else:
                        logging.error(f"unknown error in collect_ips func for raw: {i}")
            except Exception as e:
                logging.error(f"!!!!!!!! collect_ips function failed for row {i} with en error {e}")
            startpull += query_limit
        return (ip2hostname)
    else:
        logging.error(f"not able to connect to server {server_info.get('server_ip')}, with en error {r.status_code}")
        return None


def server_connectivity_check(server_info):
    if server_info.get("server_type") == "EPNM/PI":
        url = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/Devices.json?.full=true&.maxResults=5&.firstResult=0"
        check_connectivity = requests.get(url, auth=(server_info.get('server_u'), server_info.get('server_p')),
                                          verify=False)
        if check_connectivity.status_code == 200:
            print("--------------------------------------------------------------------------------------------")
            print(
                f" Connection to {server_info.get('server_type')} server: {server_info.get('server_ip')} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            return True
        else:
            print(
                f"!!!Warning!!!, I was not able to connect to {server_info.get('server_type')} server {server_info.get('server_ip')} , error: {check_connectivity.status_code}, please check credentials or user role or firewall")
            return False
    elif server_info.get("server_type") == "DNAC":
        url = f"https://{server_info.get('server_ip')}/dna/system/api/v1/auth/token"
        check_connectivity = requests.post(url, auth=(server_info.get('server_u'), server_info.get('server_p')),
                                           verify=False)
        if check_connectivity.status_code == 200:
            print("--------------------------------------------------------------------------------------------")
            print(
                f" Connection to {server_info.get('server_type')} server: {server_info.get('server_ip')} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            return True
        else:
            print(
                f"!!!Warning!!!, I was not able to connect to {server_info.get('server_type')} server {server_info.get('server_ip')} , error: {check_connectivity.status_code}, please check credentials or user role or firewall")
            return False
    elif server_info.get("server_type") == "SD-WAN":
        sdwan_server = SDwanApi(server_info)
        sdwan_server.check_connectivity()
        if sdwan_server.connectivity:
            return True
        else:
            return False
    elif server_info.get("server_type") == "NETBOX":
        netbox_server = NetboxAPI(server_info)
        netbox_server.check_connectivity()
        if netbox_server.connectivity:
            return True
        else:
            return False
    elif server_info.get("server_type") == "NETBRAIN":
        netbrain_server = NetbrainAPI(server_info)
        netbrain_server.check_connectivity()
        if netbrain_server.connectivity:
            return True
        else:
            return False
    elif server_info.get("server_type") == "CDO":
        cdo_server = CdoAPI(server_info)
        cdo_server.check_connectivity()
        if cdo_server.connectivity:
            return True
        else:
            return False
    elif server_info.get("server_type") == "SOLARWINDS":
        solarwinds_server = SolarWindsAPI(server_info)
        solarwinds_server.check_connectivity()
        if solarwinds_server.connectivity:
            return True
        else:
            return False
    elif server_info.get("server_type") == "ISE":
        ise_server = IseApi(server_info)
        ise_server.check_connectivity()
        if ise_server.connectivity:
            return True
        else:
            return False


def config():
    """this function will open config file (config.json) to get config data related to servers. In case such file does not exists user will be prompted to add such details"""
    if os.path.isfile('config.json'):
        print('Configuration file exists!')
        logging.info('Configuration file exists!')
        with open("config.json", "r") as file:
            config_data = json.loads(file.read())
        return config_data

    else:
        print("!!!Config.json file not found!!! .... will create config file")
        config_data = []
        while True:
            command = input(
                "Commands: \na - add server\nc - create configuration file and run the script\ne - exit\nPlease enter command: ").strip().lower()

            if command == "a":
                servers = {"1": "EPNM/PI", "2": "DNAC", "3": "SD-WAN", "4": "NETBOX", "5": "NETBRAIN", "6": "CDO",
                           "7": "SOLARWINDS", "8":"ISE"}

                config = {}
                server_type = input(
                    "\n Commands:\n 1 - add PI/EPNM server. \n 2 - add DNAC server. \n 3 - add SD-WAN server. \n 4 - add NETBOX server.\n 5 - add NETBRAIN server \n 6 - add CDO server \n 7 - add SOLARWINDS server \n 8 - add ISE server \n Please provide server type: ").strip()
                if not server_type or server_type not in ("1", "2", "3", "4", "5", "6", "7","8"):
                    break
                config["server_type"] = servers.get(server_type)
                print(f"server type is {servers.get(server_type)}")
                server_ip = input("please provide server IP/hostname: ").strip()
                if not server_ip:
                    break
                config['server_ip'] = server_ip
                # server_port = input("please provide server port (if you don't know, leave the field blank): ").strip()
                # if server_port:
                #    config['port'] = server_port

                if server_type in ("4", "6"):
                    server_token = getpass.getpass("please provide server token: ").strip()
                    if not server_token:
                        break
                    config['token'] = server_token
                if server_type in ("1", "2", "3", "5", "7","8"):
                    server_u = input("Please provide server User: ").strip()
                    if not server_u:
                        break
                    config['server_u'] = server_u
                    server_p = getpass.getpass("Please provide server password: ").strip()
                    if not server_p:
                        break
                    config['server_p'] = server_p
                if server_type == "5":
                    server_authentication_id = input(
                        "Please provide authentication_id (if you dont have this parameter,just leave it empty): ").strip()
                    config['authentication_id'] = server_authentication_id
                    server_group = input(
                        "Please specify group which you would like to call (if you dont have this parameter,just leave it empty): ").strip()
                    config['group'] = server_group

                # print(config)
                connectivity = server_connectivity_check(config)
                if connectivity:
                    config_data.append(config)
            elif command == "e":
                print("exiting the program")
                return None
            elif command == "c":
                with open("config.json", "w") as file:
                    file.write(json.dumps(config_data))
                    print("configuration file config.json has been created")
                    break

            else:
                print("unrecognised command")

        return config_data


def main():
    print("######################################################################")
    print("###            script author  - abalevyc@cisco.com                 ###")
    print("###        CSPC integration with PI/EPNM/DNAC/SD-WAN/NETBOX        ###")
    print("######################################################################")
    configuration = config()
    if not configuration:
        return False
    else:
        ip_hostname_manual_list = []
        with open('cspc_manual_list.csv', "r+") as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                #ip, hostname = row
                # Only extract the first two elements to avoid extra commas
                ip, hostname = row[0], row[1] 
                ip_hostname_manual_list.append({"ip": ip, "hostname": hostname})
        final_device_count = 0
        written_ips = set()  # Set to store written IP addresses
        written_hostnames = set()  # Set to store written hostnames
        with open("finalseed.csv", 'w', newline='') as file:
            for device in ip_hostname_manual_list:
                ip = device.get('ip')
                hostname = device.get('hostname')
                file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
            for server in configuration:
                logging.info(
                    f"======== Start polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                if server.get('server_type') == 'EPNM/PI':
                    dict_ip_2_hostname = collect_ips_epnm(server)
                    if dict_ip_2_hostname:
                        for i in dict_ip_2_hostname:
                            ip = i.get('ip')
                            hostname = i.get('hostname')
                            if ip not in written_ips and hostname not in written_hostnames:
                                file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                                final_device_count += 1
                                written_ips.add(ip)
                                written_hostnames.add(hostname)
                            else:
                                logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'SD-WAN':
                    sdwan_server = SDwanApi(server)
                    sdwan_server.get_jsessionid()
                    sdwan_server.get_token()
                    dict_ip_2_hostname = sdwan_server.collect_ips_sd_wan()
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'DNAC':
                    dict_ip_2_hostname = collect_ips_dnac(server)
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'NETBOX':
                    netbox_server = NetboxAPI(server)
                    dict_ip_2_hostname = netbox_server.get_all_devices()
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'CDO':
                    cdo_server = CdoAPI(server)
                    dict_ip_2_hostname = cdo_server.get_all_devices()
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'NETBRAIN':
                    netbrain_server = NetbrainAPI(server)
                    netbrain_server.get_token()
                    dict_ip_2_hostname = netbrain_server.get_all_devices()
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'SOLARWINDS':
                    solarwinds_server = SolarWindsAPI(server)
                    dict_ip_2_hostname = solarwinds_server.get_all_node_ips()
                    for i in dict_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")
                elif server.get('server_type') == 'ISE':
                    ise_server = IseApi(server)
                    list_ip_2_hostname = ise_server.get_all_network_elements()
                    for i in list_ip_2_hostname:
                        ip = i.get('ip')
                        hostname = i.get('hostname')
                        if ip not in written_ips and hostname not in written_hostnames:
                            file.write(f"{ip},{hostname},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                            written_ips.add(ip)
                            written_hostnames.add(hostname)
                        else:
                            logging.warning(f"Duplicate entry skipped: IP={ip}, Hostname={hostname}")

                logging.info(
                    f"======== Finished polling {server.get('server_type')} server: {server.get('server_ip')} ========")
        print("file finalseed.csv has been created")
        print(f"FINAL device count in CSV: {final_device_count}")
        logging.info(f"FINAL device count in CSV: {final_device_count}")
        return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler("debug.log")]
    )
    logging.info("------------------------------------------------------------------------------------")
    logging.info("-------------------------- SCRIPT JOB STARTED --------------------------------------")
    logging.info("------------------------------------------------------------------------------------")
    urllib3.disable_warnings()
    start_time = time.time()
    result = main()
    if result is True:
        try:
            p = subprocess.run(
                ["cp", "finalseed.csv", "/opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/nms_seed.csv"])
            p2 = subprocess.run(
                ["chmod", "777", "/opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/nms_seed.csv"])
            print("nms_seed.csv have been copied to /opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/")
            print("permitions 777 has been granted to nms_seed.csv")
            print(f"time taken {time.time() - start_time}")
        except Exception as e:
            print(f"Was not able to copy nms_seed.csv to SeedFileMgmt folder with an error: {e}")
            logging.error(f"was not able to copy nms_seed.csv to SeedFileMgmt folder with an error: {e}")
    else:
        logging.error(f"csv file is empty")
    logging.info("------------------------------------------------------------------------------------")
    logging.info("-------------------------- SCRIPT JOB finished --------------------------------------")
