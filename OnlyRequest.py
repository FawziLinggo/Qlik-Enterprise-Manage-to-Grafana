import requests, json, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from prometheus_client import start_http_server, Summary,Counter,Gauge,Info
import logging as log

# Set log level
log.basicConfig(level=log.INFO ,format='%(asctime)s - %(levelname)s - %(message)s')


# Remove WARN SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SessionID = '0gTjdpeSzk343RccblWjhw'
XSRFTOKEN = 'TQYPeK8OsLONGfpLqueTUQ'
PORT = 8899
Header = {
    'Cookie': 'EnterpriseManager.SessionID=' + SessionID + '; XSRF-TOKEN=' + XSRFTOKEN,
    'X-XSRF-TOKEN': XSRFTOKEN,
    }

base_url = 'https://qlikqemalldata/attunityenterprisemanager/rest/'

server_summary_info = Gauge('qlik_enterprise_manager_server_summary', 'Total server', ['status'])
server_task_info = Gauge('qlik_enterprise_manager_task_summary', 'Total task', ['status'])
servers_status_utilization_status_disk = Gauge('qlik_enterprise_manager_servers_disk_utilization_bytes', 'Disk utilization in bytes', ['serverName', 'metricType'])
servers_status_utilization_status_memory = Gauge('qlik_enterprise_manager_servers_memory_utilization_bytes', 'Memory utilization in bytes', ['serverName', 'metricType'])
servers_status_utilization_status_cpu = Gauge('qlik_enterprise_manager_servers_cpu_percentage', 'CPU utilization percentage', ['serverName'])

def helper_fix_bytes_to_mb(bytes):
    # two decimal places
    return round(bytes / (1024 * 1024), 2)

def handleHealthCheck(response_header):
    status_header = response_header['Application-Status']
    if status_header == '440':
        return response_header['Application-Detailed-Message']
    return status_header
    

def getServerSummary():
    url = base_url + 'servers/status/summary'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == '200':
        jsonData = json.loads(response.text)
        totalServer = jsonData['total']
        totalServerSuccess = jsonData['success']
        try:
            totalServerError = jsonData['error']
            server_summary_info.labels('success').set(totalServerSuccess)
            server_summary_info.labels('error').set(totalServerError)
            server_summary_info.labels('total').set(totalServer)
        except Exception as e:
            log.error('Error: ' + str(e))
            server_summary_info.labels('success').set(totalServerSuccess)
            server_summary_info.labels('error').set(0)
            server_summary_info.labels('total').set(totalServer)


    else:
        log.error('Login failed with error: ' + handleHealthCheck(response.headers))
        exit(1)


def getTaskSummary():
    url = base_url + 'tasks/summary'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == '200':
        try: 
            jsonData = json.loads(response.text)
            totalTask = jsonData['total']
            totalTaskRunning = jsonData['running']
            totalTaskStopped = jsonData['stopped']
            totalTaskError = jsonData['error']
            server_task_info.labels('running').set(totalTaskRunning)
            server_task_info.labels('stopped').set(totalTaskStopped)
            server_task_info.labels('error').set(totalTaskError)
            server_task_info.labels('total').set(totalTask)
        except Exception as e:
            log.error('Error: ' + str(e))
            server_task_info.labels('running').set(totalTaskRunning)
            server_task_info.labels('stopped').set(totalTaskStopped)
            server_task_info.labels('error').set(0)
            server_task_info.labels('total').set(totalTask)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response.headers))
        exit(1)

def updateUtilizationStatus():
    url = base_url + 'servers/'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == '200':
        jsonData = json.loads(response.text)
        for server_data in jsonData['servers']:
            # Mendapatkan nama server
            
            serverName = server_data['server_definition']['name']

            # Mendapatkan informasi disk utilization
            diskUtilizationInfo = server_data['server_status']['utilization_status']['disk_utilization_info']
            bytesTotalDisk = diskUtilizationInfo['bytes_total']
            bytesUsedDisk = diskUtilizationInfo['bytes_used']
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='total_disk').set(helper_fix_bytes_to_mb(bytesTotalDisk))
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='used_disk').set(helper_fix_bytes_to_mb(bytesUsedDisk))

            # Mendapatkan informasi memory utilization
            memoryUtilizationInfo = server_data['server_status']['utilization_status']['memory_utilization_info']
            bytesTotalMemory = memoryUtilizationInfo['bytes_total']
            bytesUsedMemory = memoryUtilizationInfo['bytes_used']
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='total_memory').set(helper_fix_bytes_to_mb(bytesTotalMemory))
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='used_memory').set(helper_fix_bytes_to_mb(bytesUsedMemory))

            # Mendapatkan informasi CPU utilization
            try:
                cpuUtilizationInfo = server_data['server_status']['utilization_status']['server_cpu_info']
                cpuPercentage = cpuUtilizationInfo['machine_cpu_percentage']
                servers_status_utilization_status_cpu.labels(serverName=serverName).set(cpuPercentage)
            except :
                servers_status_utilization_status_cpu.labels(serverName=serverName).set(0)


def avgMaxMachineCPU():
    url = base_url + 'status/summary'

if __name__ == '__main__':
    start_http_server(PORT)
    log.info('Server started on port ' + str(PORT))
    while True:
        getServerSummary()
        getTaskSummary()
        updateUtilizationStatus()
        time.sleep(0.5)    
