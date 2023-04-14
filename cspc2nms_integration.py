import requests
import getpass
import time
import logging
import json
import os
import subprocess
import urllib3

class NetboxAPI:
    def __init__(self, server_config):
        self.server_type = server_config.get('server_type')
        self.token = server_config.get('token')
        self.ip = server_config.get('server_ip')
        self.port = server_config.get('port', '8000')
        self.headers = {'Content-Type': 'application/json',
                        'Authorization': f'Token {self.token}'}
        self.url_all_devices = f'https://{self.ip}/api/dcim/devices/?manufacturer=cisco&status=active&'
        self.connectivity = False
        self.max_limit = 50
    def check_connectivity(self):
        print(self.url_all_devices)
        try:
            response = requests.get(self.url_all_devices, headers=self.headers, timeout=10)
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
            "manufacturer":"cisco",
            "has_primary_ip": True,
            "status": "active"
        }
        devices = []
        ip2hostname = []
        url = self.url_all_devices
        while url:
            print(f'url: {url}')
            response = requests.get(url, json=payload,headers=self.headers)
            if response.status_code == 200:
                data = response.json()

                devices += data['results']

                url = data['next']  # get the next page URL, if any
            else:
                print(f'Error getting devices: {response.status_code}')
                return None
        print(f'all device count: {len(devices)}')
        for device in devices:
            
            ip2hostname.append(
                {"ip": device.get('primary_ip4').get('address').split('/')[0], "hostname": device.get("name")})
        return ip2hostname



class SD_wan_authentication:
    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}

        response = requests.post(url=url, data=payload, verify=False)
        if response.ok:
            try:
                cookies = response.headers["Set-Cookie"]
                jsessionid = cookies.split(";")
                return(jsessionid[0])
            except:
                logging.error("No valid JSESSION ID returned")
                print("No valid JSESSION ID returned\n")
                return None
        else:
            print(f"connection to {vmanage_host} got failed with en error: {response.status_code}")
            return None
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        api = "/dataservice/client/token"
        url = base_url + api
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None
def collect_ips_sd_wan(server_info):
    """this function will check all devices and return dictionary with {"ip":"value","hostname":"value"}"""
    print(f"retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    ip2hostname = []
    Auth = SD_wan_authentication()
    jsessionid = Auth.get_jsessionid(server_info.get('server_ip'), server_info.get('port'), server_info.get('server_u'),
                                     server_info.get('server_p'))
    if jsessionid:
        token = Auth.get_token(server_info.get('server_ip'), server_info.get('port'), jsessionid)
        if token is not None:
            header = {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            header = {'Content-Type': "application/json", 'Cookie': jsessionid}
        result = requests.get(url=f"https://{server_info.get('server_ip')}/dataservice/device", headers=header, verify=False)
        if result.ok:
            device_list = result.json().get("data")
            for device in device_list:
                if device.get("reachability") != "reachable":
                    logging.error(f"device: {device.get('system-ip')} is not reachable")
                elif device.get('system-ip'):
                    ip2hostname.append({"ip":device.get('system-ip'),"hostname": device.get("host-name",device.get('system-ip'))})
            return ip2hostname
        else:
            logging.error(f"devices API call got failed with en error {result.status_code}")
            return None
    else:
        print(f"not able to login to {server_info.get('server_type')}: {server_info.get('server_ip')}")
        return None
def collect_ips_dnac(server_info):
    """this function will check all devices and return dictionary with {"ip":"value","hostname":"value"}"""
    print(f"retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    ip2hostname = []
    response = requests.post(f"https://{server_info.get('server_ip')}/dna/system/api/v1/auth/token", auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
    try:
        token = response.json()['Token']
        headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
        response2 = requests.get(f"https://{server_info.get('server_ip')}/dna/intent/api/v1/network-device", headers=headers, verify=False)
        for device in response2.json().get('response'):
            if device.get('reachabilityStatus') != 'Reachable':
                logging.error(f"device: {device.get('managementIpAddress')} is not reachable")
            elif device.get('managementIpAddress'):
                ip2hostname.append({"ip":device.get('managementIpAddress'), "hostname":device.get('hostname',device.get('managementIpAddress'))})
        return ip2hostname
    except Exception as e:
        logging.error(f'collection devices from  DNAC got failed with en error: {e}')
        return None
def collect_ips_epnm(server_info):
    """this function will check all devices and return dictionary with {"ip":"value","hostname":"value"}"""
    print(f"retrieving data from {server_info.get('server_type')} server: {server_info.get('server_ip')}")
    url = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/InventoryDetails.json"
    r = requests.get(url, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
    if r.ok:
        device_count = int(r.json().get('queryResponse').get('@count'))
        #print(f"Device count: {device_count}")
        r2 = requests.get(url=f"https://{server_info.get('server_ip')}/webacs/api/v4/op/rateService/rateLimits.json", auth=(server_info.get('server_u'),server_info.get('server_p')), verify=False)
        print(f"query limit: {r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']}")
        query_limit = r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']
        logging.info(f"query limit: {r2.json().get('mgmtResponse').get('rateLimitsDTO')[0]['limitUnpagedQuery']} for server: {server_info.get('server_ip')}")
        startpull = 0
        ip2hostname = []
        list_of_ips = []
        while startpull < device_count:
            print(f"========= Polling device IPs from: {startpull} to: {startpull+query_limit} ==========")
            devices_ip = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/Devices.json?.full=true&.maxResults={query_limit}&.firstResult={startpull}"
            r3 = requests.get(devices_ip, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
            data = r3.json().get('queryResponse').get('entity')
            try:
                for i in data:
                    if i.get('devicesDTO').get('reachability') !='REACHABLE':
                        logging.error(f"devices: {i.get('devicesDTO').get('ipAddress')} is not reachable")
                    elif i.get('devicesDTO').get('deviceType') == 'Unsupported Cisco Device':
                        logging.error(f"devices: {i.get('devicesDTO').get('ipAddress')} is not supported")
                    elif i.get('devicesDTO').get('ipAddress') and i.get('devicesDTO').get('deviceName'):
                        ip2hostname.append({"ip":i['devicesDTO']['ipAddress'],"hostname":i['devicesDTO']['deviceName']})
                        list_of_ips.append(i['devicesDTO']['ipAddress'])
                    elif i.get('devicesDTO').get('ipAddress') and not i.get('devicesDTO').get('deviceName'):
                        logging.error(f"device {i.get('devicesDTO').get('ipAddress')} has no hostname in API hence setting up ip as hostname, function collect_ips()")
                        ip2hostname.append({"ip": i['devicesDTO']['ipAddress'], "hostname": i['devicesDTO']['ipAddress']})
                        list_of_ips.append(i['devicesDTO']['ipAddress'])
                    else:
                        logging.error(f"unknown error in collect_ips func for raw: {i}")
            except Exception as e:
                logging.error(f"!!!!!!!! collect_ips function failed for row {i} with en error {e}")
            startpull += query_limit
        #print(ip2hostname)
        return(ip2hostname)
    else:
        logging.error(f"not able to connect to server {server_info.get('server_ip')}, with en error {r.status_code}")
        return None

def server_connectivity_check(server_info):
    if server_info.get("server_type") == "EPNM/PI":
        url = f"https://{server_info.get('server_ip')}/webacs/api/v4/data/Devices.json?.full=true&.maxResults=5&.firstResult=0"
        check_connectivity = requests.get(url, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
        if check_connectivity.status_code == 200:
            print("--------------------------------------------------------------------------------------------")
            print(f" Connection to {server_info.get('server_type')} server: {server_info.get('server_ip')} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            return True
        else:
            print(f"!!!Warning!!!, I was not able to connect to {server_info.get('server_type')} server {server_info.get('server_ip')} , error: {check_connectivity.status_code}, please check credentials or user role or firewall")
            return False
    elif server_info.get("server_type") == "DNAC":
        url = f"https://{server_info.get('server_ip')}/dna/system/api/v1/auth/token"
        check_connectivity = requests.post(url, auth=(server_info.get('server_u'), server_info.get('server_p')), verify=False)
        if check_connectivity.status_code == 200:
            print("--------------------------------------------------------------------------------------------")
            print(f" Connection to {server_info.get('server_type')} server: {server_info.get('server_ip')} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            return True
        else:
            print(f"!!!Warning!!!, I was not able to connect to {server_info.get('server_type')} server {server_info.get('server_ip')} , error: {check_connectivity.status_code}, please check credentials or user role or firewall")
            return False
    elif server_info.get("server_type") == "SD-WAN":
        Auth = SD_wan_authentication()
        jsessionid = Auth.get_jsessionid(server_info.get('server_ip'), server_info.get('port'), server_info.get('server_u'),server_info.get('server_p'))
        if jsessionid:
            print("--------------------------------------------------------------------------------------------")
            print(
                f" Connection to {server_info.get('server_type')} server: {server_info.get('server_ip')} was SUCCESSFUL. Added server to the configuration ")
            print("--------------------------------------------------------------------------------------------")
            return True
        else:
            print(
                f"!!!Warning!!!, I was not able to connect to {server_info.get('server_type')} server {server_info.get('server_ip')}, please check credentials or user role or firewall")
            return False
    elif server_info.get("server_type") == "NETBOX":
        netbox_server = NetboxAPI(server_info)
        netbox_server.check_connectivity()
        if netbox_server.connectivity:
            return True
        else:
            return False
def config():
    """this function will open config file (config.json) to get config data related to servers. In case such file does not exists user will be prompted to add such details"""
    if  os.path.isfile('./config.json'):
        print('Configuration file exists!')
        logging.info('Configuration file exists!')
        with open("./config.json", "r") as file:
            config_data = json.loads(file.read())
        return config_data

    else:
        print("!!!Config.json file not found!!! .... will create config file")
        config_data = []
        while True:
            command = input(
                "Commands: \na - add server\nc - create configuration file and run the script\ne - exit\nPlease enter command: ").strip().lower()

            if command == "a":
                servers = {"1": "EPNM/PI","2":"DNAC","3":"SD-WAN","4":"NETBOX"}

                config = {}
                server_type = input("\n Commands:\n 1 - add PI/EPNM server. \n 2 - add DNAC server. \n 3 - add SD-WAN server. \n 4 - add NETBOX server.\n Please provide server type: ").strip()
                if not server_type or server_type not in ("1","2","3","4"):
                    break
                config["server_type"] = servers.get(server_type)
                print(f"server type is {servers.get(server_type)}")
                server_ip = input("please provide server IP: ").strip()
                if not server_ip:
                    break
                config['server_ip'] = server_ip
                #server_port = input("please provide server port (if you don't know, leave the field blank): ").strip()
                #if server_port:
                #    config['port'] = server_port

                if server_type == "4":
                    server_token = input("please provide server token: ").strip()
                    if not server_token:
                        break
                    config['token'] = server_token
                if server_type in ("1","2","3"):
                    server_u = input("Please provide server User: ").strip()
                    if not server_u:
                        break
                    config['server_u'] = server_u
                    server_p = getpass.getpass("Please provide server password: ").strip()
                    if not server_p:
                        break
                    config['server_p'] = server_p
                #print(config)
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
            final_device_count = 0
            with open("finalseed.csv", 'w', newline='') as file:
                for server in configuration:
                    if server.get('server_type') == 'EPNM/PI':
                        logging.info(f"======== Start polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                        dict_ip_2_hostname = collect_ips_epnm(server)
                        if dict_ip_2_hostname:
                            list_of_ips = [i.get('ip') for i in dict_ip_2_hostname]
                            logging.info(f"total amount of devices for {server.get('server_type')} server: {server.get('server_ip')}: {len(set(list_of_ips))}")
                            for i in dict_ip_2_hostname:
                                file.write(f"{i.get('ip')},{i.get('hostname')},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                                final_device_count += 1
                        logging.info(f"======== Finished polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                    elif server.get('server_type') == 'SD-WAN':
                        logging.info(f"======== Start polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                        dict_ip_2_hostname = collect_ips_sd_wan(server)
                        if dict_ip_2_hostname:
                            list_of_ips = [i.get('ip') for i in dict_ip_2_hostname]
                            logging.info(
                            f"total amount of devices for {server.get('server_type')} server: {server.get('server_ip')}: {len(set(list_of_ips))}")
                            for i in dict_ip_2_hostname:
                                file.write(f"{i.get('ip')},{i.get('hostname')},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                                final_device_count += 1
                        logging.info(
                            f"======== Finished polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                    elif server.get('server_type') == 'DNAC':
                        logging.info(f"======== start polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                        dict_ip_2_hostname = collect_ips_dnac(server)
                        list_of_ips = [i.get('ip') for i in dict_ip_2_hostname]
                        logging.info(
                            f"total amount of devices for {server.get('server_type')} server: {server.get('server_ip')}: {len(set(list_of_ips))}")
                        for i in dict_ip_2_hostname:
                            file.write(f"{i.get('ip')},{i.get('hostname')},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
                        logging.info(
                            f"======== Finished polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                    elif server.get('server_type')  == 'NETBOX':
                        logging.info(
                            f"======== start polling {server.get('server_type')} server: {server.get('server_ip')} ========")
                        netbox_server = NetboxAPI(server)
                        dict_ip_2_hostname = netbox_server.get_all_devices()
                        for i in dict_ip_2_hostname:
                            file.write(f"{i.get('ip')},{i.get('hostname')},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n")
                            final_device_count += 1
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
            p = subprocess.run(["cp", "finalseed.csv", "/opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/nms_seed.csv"])
            p2 = subprocess.run(["chmod", "777", "/opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/nms_seed.csv"])
            print("nms_seed.csv have been copied to /opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/")
            print("permitions 777 has been granted to nms_seed.csv")
            print(f"time taken {time.time()-start_time}")
        except Exception as e:
            print(f"Was not able to copy nms_seed.csv to SeedFileMgmt folder with an error: {e}")
            logging.error(f"was not able to copy nms_seed.csv to SeedFileMgmt folder with an error: {e}")
    else:
        logging.error(f"csv file is empty")
    logging.info("------------------------------------------------------------------------------------")
    logging.info("-------------------------- SCRIPT JOB finished --------------------------------------")
