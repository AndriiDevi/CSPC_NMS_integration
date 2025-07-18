# CSPC_NMS_integration

This script was designed to integrate [Cisco CSPC](https://software.cisco.com/download/home/286312935/type) product with different NMS systems: DNAC, ISE, EPNM, PI, SD-WAN, NETBOX.

it will get list of devices and create CSPC format seed file with IPs and Hosntames.

# Installation:
```
git clone https://github.com/AndriiDevi/CSPC_NMS_integration.git
```
1. Script collects only IP and Hostname from NMS (no device credentials collected).

2. Scrip will create config.json to store nms details in plain text.

3. Script is checking connectivity to the server before add it to configuration file.

4. Script will exclude devices marked unreachable by NMS.

5. Script will create seed file (nms_seed.csv) and copy it to /opt/cisco/ss/adminshell/applications/CSPC/data/SeedFileMgmt/

6. All errors and other details related to script work you can find in debug.log (will be created after first run in the same folder where the python script is located) 

7.Schedule a script with cron job

8.Last step to schedule import seed file with using global credentials in CSPC

 

User will need to provide NMS details below:

1. Ip address/hostname

2. User name

3. Password

4. Token (for netbox, netbrain)

5. For Netbrain there is a groups with cisco devices should be created

 

Username role requirements:
 

EPNM/PI - user should have NBI read role to be able to make API call to the server.

DNAC - OBSERVER-ROLE is sufficient for user to get API access

SD-WAN - TBU

NETBOX - no user, token is needed

NETBRAIN - no user, token is needed, and group name

