import requests, json, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from prometheus_client import start_http_server, Summary,Counter,Gauge,Info
import logging as log
from datetime import datetime, timedelta


# Set log level
log.basicConfig(level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line %(lineno)d')


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
servers_status_utilization_status_disk_avg = Gauge('qlik_enterprise_manager_servers_disk_utilization_avg_percentage', 'Disk utilization average percentage', ['serverName'])
servers_status_utilization_status_memory_avg = Gauge('qlik_enterprise_manager_servers_memory_utilization_avg_percentage', 'Memory utilization average percentage', ['serverName'])
servers_status_utilization_status_attunity_cpu_avg = Gauge('qlik_enterprise_manager_server_attunity_cpu_avg_percentage', 'Attunity CPU utilization average percentage', ['serverName'])
servers_status_utilization_status_machine_cpu_avg = Gauge('qlik_enterprise_manager_server_machine_cpu_avg_percentage', 'Machine CPU utilization average percentage', ['serverName'])
servers_status_utilization_status_full_load_avg_throughput = Gauge('qlik_enterprise_manager_server_full_load_avg_throughput_bytes', 'Full load average throughput in bytes', ['serverName'])

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
            # Get Server Name
            serverName = server_data['server_definition']['name']

            # Get INFO disk utilization
            diskUtilizationInfo = server_data['server_status']['utilization_status']['disk_utilization_info']
            bytesTotalDisk = diskUtilizationInfo['bytes_total']
            bytesUsedDisk = diskUtilizationInfo['bytes_used']
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='total_disk').set(helper_fix_bytes_to_mb(bytesTotalDisk))
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='used_disk').set(helper_fix_bytes_to_mb(bytesUsedDisk))

            # Get INFO memory utilization
            memoryUtilizationInfo = server_data['server_status']['utilization_status']['memory_utilization_info']
            bytesTotalMemory = memoryUtilizationInfo['bytes_total']
            bytesUsedMemory = memoryUtilizationInfo['bytes_used']
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='total_memory').set(helper_fix_bytes_to_mb(bytesTotalMemory))
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='used_memory').set(helper_fix_bytes_to_mb(bytesUsedMemory))

            # Get INFO CPU utilization
            try:
                cpuUtilizationInfo = server_data['server_status']['utilization_status']['server_cpu_info']
                cpuPercentage = cpuUtilizationInfo['machine_cpu_percentage']
                servers_status_utilization_status_cpu.labels(serverName=serverName).set(cpuPercentage)
            except :
                servers_status_utilization_status_attunity_cpu_avg.labels(serverName=serverName).set(0)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response.headers))
        exit(1)

def avgMaxMachine_utilization():
    url_avg_memory = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-memory'
    url_avg_disk = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-io'
    url_avg_attunity_cpu = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-attunity-cpu'
    url_avg_machine_cpu = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-machine-cpu'
    url_load_full_avg_throughput = base_url + 'analytics/server/replicate/trends/full-load/server-avg-target-throughput-changes'

    end_time = datetime.utcnow()
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    start_time_ten_minutes_ago = end_time - timedelta(minutes=10)
    start_time_ten_minutes_ago_str = start_time_ten_minutes_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    request_body = {
            "start": start_time_ten_minutes_ago_str,
            "end": end_time_str,
            "trend_level": ["Minute"],
            "limit": 0,
            "order_by": ["Avg Memory"],
            "order_direction": ["descending"]
        }
    response_avg_memory = requests.put(url_avg_memory, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == '200':
        jsonData = json.loads(response_avg_memory.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgMemory = server_data_avg['serverTrends']['avg_memory'][0]['value']
            servers_status_utilization_status_memory_avg.labels(serverName=serverName).set(avgMemory)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)

    response_avg_disk = requests.put(url_avg_disk, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_disk.headers) == '200':
        jsonData = json.loads(response_avg_disk.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgDisk = server_data_avg['serverTrends']['avg_IO'][0]['value']
            servers_status_utilization_status_disk_avg.labels(serverName=serverName).set(avgDisk)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)
        
    response_avg_attunity_cpu = requests.put(url_avg_attunity_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_attunity_cpu.headers) == '200':
        jsonData = json.loads(response_avg_attunity_cpu.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgCpu = server_data_avg['serverTrends']['avg_attunity_CPU'][0]['value']
            servers_status_utilization_status_attunity_cpu_avg.labels(serverName=serverName).set(avgCpu)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)
    
    response_avg_machine_cpu = requests.put(url_avg_machine_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_machine_cpu.headers) == '200':
        jsonData = json.loads(response_avg_machine_cpu.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgCpu = server_data_avg['serverTrends']['avg_machine_CPU'][0]['value']
            servers_status_utilization_status_machine_cpu_avg.labels(serverName=serverName).set(avgCpu)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)

    response_load_full_avg_throughput = requests.put(url_load_full_avg_throughput, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_load_full_avg_throughput.headers) == '200':
        jsonData = json.loads(response_load_full_avg_throughput.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgThroughput = server_data_avg['serverTrends']['avg_target_throughput_changes'][0]['value']
            servers_status_utilization_status_full_load_avg_throughput.labels(serverName=serverName).set(avgThroughput)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)
        
if __name__ == '__main__':
    start_http_server(PORT)
    log.info('Server started on port ' + str(PORT))
    while True:
        getServerSummary()
        getTaskSummary()
        updateUtilizationStatus()
        avgMaxMachine_utilization()
        time.sleep(1)    
