import requests, json, time
from urllib3.exceptions import InsecureRequestWarning
from prometheus_client import start_http_server, Summary,Counter,Gauge,Info
import logging as log
from datetime import datetime, timedelta
import configparser

# Set log level
log.basicConfig(level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line %(lineno)d')


# Remove WARN SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


config = configparser.ConfigParser()		
config.read("config.ini")
SERVER_PROPERTIES = config['SERVER']
SessionID = SERVER_PROPERTIES['Session_ID']
XSRFTOKEN = SERVER_PROPERTIES['X_SRF_TOKEN']
PORT = int(SERVER_PROPERTIES['PORT'])
Header = {
    'Cookie': 'EnterpriseManager.SessionID=' + SessionID + '; XSRF-TOKEN=' + XSRFTOKEN,
    'X-XSRF-TOKEN': XSRFTOKEN,
    }

base_url = SERVER_PROPERTIES['BASE_URL'] +'/attunityenterprisemanager/rest/'
interval_sleep = int(SERVER_PROPERTIES['Interval_Time_in_Seconds'])

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
servers_status_utilization_status_full_load_avg_latency = Gauge('qlik_enterprise_manager_server_full_load_avg_latency_seconds', 'Full load average latency in seconds', ['serverName'])
task_utilization_status_avg_memory = Gauge('qlik_enterprise_manager_task_avg_memory_bytes', 'Task average memory in bytes', ['taskName'])
task_utilization_status_avg_cpu = Gauge('qlik_enterprise_manager_task_avg_cpu_percentage', 'Task average CPU in percentage', ['taskName'])
task_utilization_status_avg_disk = Gauge('qlik_enterprise_manager_task_avg_disk_percentage', 'Task average disk in percentage', ['taskName'])
task_utilization_status_avg_source_throughput = Gauge('qlik_enterprise_manager_task_avg_source_throughput_bytes', 'Task average source throughput in bytes', ['taskName'])
task_utilization_status_avg_target_throughput = Gauge('qlik_enterprise_manager_task_avg_target_throughput_bytes', 'Task average target throughput in bytes', ['taskName'])
task_utilization_status_avg_source_latency = Gauge('qlik_enterprise_manager_task_avg_source_latency_seconds', 'Task average source latency in seconds', ['taskName'])
task_utilization_status_avg_apply_latency = Gauge('qlik_enterprise_manager_task_avg_target_apply_seconds', 'Task average apply latency in seconds', ['taskName'])

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
    url_load_full_avg_latency = base_url + 'analytics/server/replicate/trends/full-load/server-avg-apply-latency'

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
    
    response_load_full_avg_latency = requests.put(url_load_full_avg_latency, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_load_full_avg_latency.headers) == '200':
        jsonData = json.loads(response_load_full_avg_latency.text)['serversTrends']
        for server_data_avg in jsonData:
            serverName = server_data_avg['serverName']
            avgLatency = server_data_avg['serverTrends']['avg_apply_latency'][0]['value']
            servers_status_utilization_status_full_load_avg_latency.labels(serverName=serverName).set(avgLatency)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)

def avgTask_utilization():
    url_task_avg_memory = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-memory'
    url_task_avg_cpu = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-cpu'
    url_task_avg_disk = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-disk-usage'
    url_task_avg_source_target_throughput_latency = base_url + 'analytics/server/replicate/capacity-planning/change-processing-performance/avg-source-and-target-throughput-with-avg-source-and-apply-latency'

    end_time = datetime.utcnow()
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    start_time_60_minutes_ago = end_time - timedelta(minutes=60)
    start_time_60_minutes_ago_str = start_time_60_minutes_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    request_body = {
            "start": start_time_60_minutes_ago_str,
            "end": end_time_str,
            "trend_level": [
                "Hourly"
            ],
            "limit": 0
            }
    response_avg_memory = requests.put(url_task_avg_memory, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == '200':
        jsonData = json.loads(response_avg_memory.text)['avg_memory_by_task']
        for server_data_avg in jsonData:
            serverName = server_data_avg['server']
            TaskName = server_data_avg['task'].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgMemory = server_data_avg['avg_memory'][0]['value']
            task_utilization_status_avg_memory.labels(taskName=serverTaskName).set(avgMemory)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_memory.headers))
        log.error('Error: ' + str(response_avg_memory.headers))
        exit(1)

    response_avg_cpu = requests.put(url_task_avg_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == '200':
        jsonData = json.loads(response_avg_cpu.text)['avg_CPU_by_task']
        for server_data_avg in jsonData:
            serverName = server_data_avg['server']
            TaskName = server_data_avg['task'].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgCPU = server_data_avg['avg_CPU'][0]['value']
            task_utilization_status_avg_cpu.labels(taskName=serverTaskName).set(avgCPU)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_cpu.headers))
        log.error('Error: ' + str(response_avg_cpu.headers))
        exit(1)

    response_avg_disk = requests.put(url_task_avg_disk, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_disk.headers) == '200':
        jsonData = json.loads(response_avg_disk.text)['avg_disk_usage_by_task']
        for server_data_avg in jsonData:
            serverName = server_data_avg['server']
            TaskName = server_data_avg['task'].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgDisk = server_data_avg['avg_disk_usage'][0]['value']
            task_utilization_status_avg_disk.labels(taskName=serverTaskName).set(avgDisk)
    else:
        log.error('Login failed with error: ' + handleHealthCheck(response_avg_disk.headers))
        log.error('Error: ' + str(response_avg_disk.headers))
        exit(1)
    
    response_avg_throughput_latency = requests.put(url_task_avg_source_target_throughput_latency, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_throughput_latency.headers) == '200':
        jsonData = json.loads(response_avg_throughput_latency.text)
        task_utilization_status_avg_source_throughput.labels(taskName='avg_source_throughput').set(jsonData['avg_source_throughput'][0]['value'])
        task_utilization_status_avg_target_throughput.labels(taskName='avg_target_throughput').set(jsonData['avg_target_throughput'][0]['value'])
        task_utilization_status_avg_source_latency.labels(taskName='avg_source_latency').set(jsonData['avg_source_latency'][0]['value'])
        task_utilization_status_avg_apply_latency.labels(taskName='avg_apply_latency').set(jsonData['avg_apply_latency'][0]['value'])

        

if __name__ == '__main__':
    start_http_server(PORT)
    log.info('Server started on port ' + str(PORT))
    while True:
        getServerSummary()
        getTaskSummary()
        updateUtilizationStatus()
        avgMaxMachine_utilization()
        avgTask_utilization()
        time.sleep(1)    
