import requests, json, time
from urllib3.exceptions import InsecureRequestWarning
from prometheus_client import start_http_server, Gauge
import logging as log
from datetime import datetime, timedelta
import configparser

# Set log level
log.basicConfig(level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line %(lineno)d')


# Remove WARN SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Constants:
    ERROR_CODE = '440'
    SUCCESS_CODE = '200'
    HEADER_APPLICATION_STATUS = 'Application-Status'
    HEADER_APPLICATION_DETAILED_MESSAGE = 'Application-Detailed-Message'
    HEADER_X_XSRF_TOKEN = 'X-XSRF-TOKEN'
    HEADER_COKKIE = 'Cookie'
    FIRST_ELEMENT = 0
    EMPTY_STRING = ''
    EMPTY_INT = 0
    FIELD_TOTAL = 'total'
    FIELD_STATUS = 'status'
    FIELD_SUCCESS = 'success'
    FIELD_ERROR = 'error'
    FIELD_STOPPED = 'stopped'
    FIELD_RUNNING = 'running'
    FIELD_VALUE = 'value'
    FIELD_NAME = 'name'
    FIELD_SERVER_NAME = 'serverName'
    FIELD_SERVER = 'server'
    FIELD_SERVERS = 'servers'
    FIELD_SEVER_DEFINITION ='server_definition'
    FIELD_SERVER_STATUS = 'server_status'
    FIELD_SERVERS_TRERND = 'serversTrends'
    FIELD_SERVER_TRERND = 'serverTrends'
    FIELD_TASK = 'task'
    FIELD_TASK_NAME = 'taskName'
    FIELD_METRIC_TYPE = 'metricType'
    FIELD_AVG_CPU = 'avg_CPU'
    FIELD_AVG_MEMORY = 'avg_memory'
    FIELD_AVG_IO = 'avg_IO'
    FIELD_AVG_ATTUNITY_CPU = 'avg_attunity_CPU'
    FIELD_AVG_MACHINE_CPU = 'avg_machine_CPU'
    FIELD_AVG_TARGET_THROUGHPUT_CHANGES = 'avg_target_throughput_changes'
    FIELD_AVG_APPLY_LATENCY = 'avg_apply_latency'
    FIELD_AVG_SOURCE_THROUGHPUT = 'avg_source_throughput'
    FIELD_AVG_SOURCE_LATENCY = 'avg_source_latency'
    FIELD_AVG_TARGET_THROUGHPUT = 'avg_target_throughput'
    FIELD_UTILIZATION_STATUS = 'utilization_status'
    FIELD_DISK_UTILIZATION_INFO = 'disk_utilization_info'
    FIELD_MEMORY_UTILIZATION_INFO = 'memory_utilization_info'
    FIELD_SERVER_CPU_INFO = 'server_cpu_info'
    FIELD_BYTES_TOTAL = 'bytes_total'
    FIELD_BYTES_USED = 'bytes_used'
    FIELD_AVG_MEMORY_BY_TASK = 'avg_memory_by_task'
    FIELD_AVG_DISK_USAGE = 'avg_disk_usage'
    FIELD_AVG_DISK_USAGE_BY_TASK = 'avg_disk_usage_by_task'
    FIELD_AVG_AVG_CPU_BY_TASK='avg_CPU_by_task'
    STR_TIME_FORMAT="%Y-%m-%dT%H:%M:%S.000Z"

    

config = configparser.ConfigParser()		
config.read("config.ini")
SERVER_PROPERTIES = config[Constants.FIELD_SERVER.upper()]
SessionID = SERVER_PROPERTIES['Session_ID']
XSRFTOKEN = SERVER_PROPERTIES['X_SRF_TOKEN']
PORT = int(SERVER_PROPERTIES['PORT'])
Header = {
    Constants.HEADER_COKKIE: 'EnterpriseManager.SessionID=' + SessionID + '; XSRF-TOKEN=' + XSRFTOKEN,
    Constants.HEADER_X_XSRF_TOKEN: XSRFTOKEN,
    }

base_url = SERVER_PROPERTIES['BASE_URL'] +'/attunityenterprisemanager/rest/'
interval_sleep = int(SERVER_PROPERTIES['Interval_Time_in_Seconds'])

server_summary_info = Gauge('qlik_enterprise_manager_server_summary', 'Total server', [Constants.FIELD_STATUS])
server_task_info = Gauge('qlik_enterprise_manager_task_summary', 'Total task', [Constants.FIELD_STATUS])
servers_status_utilization_status_disk = Gauge('qlik_enterprise_manager_servers_disk_utilization_bytes', 'Disk utilization in bytes', [Constants.FIELD_SERVER_NAME, Constants.FIELD_METRIC_TYPE])
servers_status_utilization_status_memory = Gauge('qlik_enterprise_manager_servers_memory_utilization_bytes', 'Memory utilization in bytes', [Constants.FIELD_SERVER_NAME, Constants.FIELD_METRIC_TYPE])
servers_status_utilization_status_cpu = Gauge('qlik_enterprise_manager_servers_cpu_percentage', 'CPU utilization percentage', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_disk_avg = Gauge('qlik_enterprise_manager_servers_disk_utilization_avg_percentage', 'Disk utilization average percentage', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_memory_avg = Gauge('qlik_enterprise_manager_servers_memory_utilization_avg_percentage', 'Memory utilization average percentage', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_attunity_cpu_avg = Gauge('qlik_enterprise_manager_server_attunity_cpu_avg_percentage', 'Attunity CPU utilization average percentage', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_machine_cpu_avg = Gauge('qlik_enterprise_manager_server_machine_cpu_avg_percentage', 'Machine CPU utilization average percentage', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_full_load_avg_throughput = Gauge('qlik_enterprise_manager_server_full_load_avg_throughput_bytes', 'Full load average throughput in bytes', [Constants.FIELD_SERVER_NAME])
servers_status_utilization_status_full_load_avg_latency = Gauge('qlik_enterprise_manager_server_full_load_avg_latency_seconds', 'Full load average latency in seconds', [Constants.FIELD_SERVER_NAME])
task_utilization_status_avg_memory = Gauge('qlik_enterprise_manager_task_avg_memory_bytes', 'Task average memory in bytes', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_cpu = Gauge('qlik_enterprise_manager_task_avg_cpu_percentage', 'Task average CPU in percentage', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_disk = Gauge('qlik_enterprise_manager_task_avg_disk_percentage', 'Task average disk in percentage', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_source_throughput = Gauge('qlik_enterprise_manager_task_avg_source_throughput_bytes', 'Task average source throughput in bytes', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_target_throughput = Gauge('qlik_enterprise_manager_task_avg_target_throughput_bytes', 'Task average target throughput in bytes', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_source_latency = Gauge('qlik_enterprise_manager_task_avg_source_latency_seconds', 'Task average source latency in seconds', [Constants.FIELD_TASK_NAME])
task_utilization_status_avg_apply_latency = Gauge('qlik_enterprise_manager_task_avg_target_apply_seconds', 'Task average apply latency in seconds', [Constants.FIELD_TASK_NAME])




def helper_fix_bytes_to_mb(bytes):
    # two decimal places
    return round(bytes / (1024 * 1024), 2)

def handleHealthCheck(response_header):
    status_header = response_header[Constants.HEADER_APPLICATION_STATUS]
    if status_header == Constants.ERROR_CODE:
        return response_header[Constants.HEADER_APPLICATION_DETAILED_MESSAGE]
    return status_header
    

def handleErrorExit(header_response):
    log.error('Request failed with error: ' + handleHealthCheck(header_response))
    log.error('Error: ' + str(header_response))
    return exit(1)

def getServerSummary():
    url = base_url + 'servers/status/summary'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response.text)
        totalServer = jsonData[Constants.FIELD_TOTAL]
        totalServerSuccess = jsonData[Constants.FIELD_SUCCESS]
        try:
            totalServerError = jsonData[Constants.FIELD_ERROR]
            server_summary_info.labels(Constants.FIELD_SUCCESS).set(totalServerSuccess)
            server_summary_info.labels(Constants.FIELD_ERROR).set(totalServerError)
            server_summary_info.labels(Constants.FIELD_TOTAL).set(totalServer)
        except Exception as e:
            log.error('Error: ' + str(e))
            server_summary_info.labels(Constants.FIELD_SUCCESS).set(totalServerSuccess)
            server_summary_info.labels(Constants.FIELD_ERROR).set(Constants.EMPTY_INT)
            server_summary_info.labels(Constants.FIELD_TOTAL).set(totalServer)


    else:
        handleErrorExit(response.headers)



def getTaskSummary():
    url = base_url + 'tasks/summary'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == Constants.SUCCESS_CODE:
        try: 
            jsonData = json.loads(response.text)
            totalTask = jsonData[Constants.FIELD_TOTAL]
            totalTaskRunning = jsonData[Constants.FIELD_RUNNING]
            totalTaskStopped = jsonData[Constants.FIELD_STOPPED]
            totalTaskError = jsonData[Constants.FIELD_ERROR]
            server_task_info.labels(Constants.FIELD_RUNNING).set(totalTaskRunning)
            server_task_info.labels(Constants.FIELD_STOPPED).set(totalTaskStopped)
            server_task_info.labels(Constants.FIELD_ERROR).set(totalTaskError)
            server_task_info.labels(Constants.FIELD_TOTAL).set(totalTask)
        except Exception as e:
            log.error('Error: ' + str(e))
            server_task_info.labels(Constants.FIELD_RUNNING).set(totalTaskRunning)
            server_task_info.labels(Constants.FIELD_STOPPED).set(totalTaskStopped)
            server_task_info.labels(Constants.FIELD_ERROR).set(Constants.EMPTY_INT)
            server_task_info.labels(Constants.FIELD_TOTAL).set(totalTask)
    else:
        handleErrorExit(response.headers)


def updateUtilizationStatus():
    url = base_url + 'servers/'
    response = requests.get(url, headers=Header, verify=False)
    if handleHealthCheck(response.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response.text)
        for server_data in jsonData[Constants.FIELD_SERVERS]:
            # Get Server Name
            serverName = server_data[Constants.FIELD_SEVER_DEFINITION][Constants.FIELD_NAME]

            # Get INFO disk utilization
            diskUtilizationInfo = server_data[Constants.FIELD_SERVER_STATUS][Constants.FIELD_UTILIZATION_STATUS][Constants.FIELD_DISK_UTILIZATION_INFO]
            bytesTotalDisk = diskUtilizationInfo[Constants.FIELD_BYTES_TOTAL]
            bytesUsedDisk = diskUtilizationInfo[Constants.FIELD_BYTES_USED]
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='total_disk').set(helper_fix_bytes_to_mb(bytesTotalDisk))
            servers_status_utilization_status_disk.labels(serverName=serverName, metricType='used_disk').set(helper_fix_bytes_to_mb(bytesUsedDisk))

            # Get INFO memory utilization
            memoryUtilizationInfo = server_data[Constants.FIELD_SERVER_STATUS][Constants.FIELD_UTILIZATION_STATUS][Constants.FIELD_MEMORY_UTILIZATION_INFO]
            bytesTotalMemory = memoryUtilizationInfo[Constants.FIELD_BYTES_TOTAL]
            bytesUsedMemory = memoryUtilizationInfo[Constants.FIELD_BYTES_USED]
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='total_memory').set(helper_fix_bytes_to_mb(bytesTotalMemory))
            servers_status_utilization_status_memory.labels(serverName=serverName, metricType='used_memory').set(helper_fix_bytes_to_mb(bytesUsedMemory))

            # Get INFO CPU utilization
            try:
                cpuUtilizationInfo = server_data[Constants.FIELD_SERVER_STATUS][Constants.FIELD_UTILIZATION_STATUS][Constants.FIELD_SERVER_CPU_INFO]
                cpuPercentage = cpuUtilizationInfo['machine_cpu_percentage']
                servers_status_utilization_status_cpu.labels(serverName=serverName).set(cpuPercentage)
            except :
                servers_status_utilization_status_attunity_cpu_avg.labels(serverName=serverName).set(Constants.EMPTY_INT)
    else:
        handleErrorExit(response.headers)


def avgMaxMachine_utilization():
    url_avg_memory = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-memory'
    url_avg_disk = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-io'
    url_avg_attunity_cpu = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-attunity-cpu'
    url_avg_machine_cpu = base_url + 'analytics/server/replicate/trends/server-utilization/server-avg-machine-cpu'
    url_load_full_avg_throughput = base_url + 'analytics/server/replicate/trends/full-load/server-avg-target-throughput-changes'
    url_load_full_avg_latency = base_url + 'analytics/server/replicate/trends/full-load/server-avg-apply-latency'

    end_time = datetime.utcnow()
    end_time_str = end_time.strftime(Constants.STR_TIME_FORMAT)
    start_time_ten_minutes_ago = end_time - timedelta(minutes=10)
    start_time_ten_minutes_ago_str = start_time_ten_minutes_ago.strftime(Constants.STR_TIME_FORMAT)

    request_body = {
            "start": start_time_ten_minutes_ago_str,
            "end": end_time_str,
            "trend_level": ["Minute"],
            "limit": 0,
            "order_by": ["Avg Memory"],
            "order_direction": ["descending"]
        }
    response_avg_memory = requests.put(url_avg_memory, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_memory.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgMemory = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_MEMORY][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_memory_avg.labels(serverName=serverName).set(avgMemory)
    else:
        handleErrorExit(response_avg_memory.headers)


    response_avg_disk = requests.put(url_avg_disk, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_disk.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_disk.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgDisk = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_IO][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_disk_avg.labels(serverName=serverName).set(avgDisk)
    else:
        handleErrorExit(response_avg_disk.headers)
        
    response_avg_attunity_cpu = requests.put(url_avg_attunity_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_attunity_cpu.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_attunity_cpu.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgCpu = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_ATTUNITY_CPU][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_attunity_cpu_avg.labels(serverName=serverName).set(avgCpu)
    else:
        handleErrorExit(response_avg_attunity_cpu.headers)
    
    response_avg_machine_cpu = requests.put(url_avg_machine_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_machine_cpu.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_machine_cpu.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgCpu = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_MACHINE_CPU][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_machine_cpu_avg.labels(serverName=serverName).set(avgCpu)
    else:
        handleErrorExit(response_avg_machine_cpu.headers)

    response_load_full_avg_throughput = requests.put(url_load_full_avg_throughput, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_load_full_avg_throughput.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_load_full_avg_throughput.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgThroughput = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_TARGET_THROUGHPUT_CHANGES][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_full_load_avg_throughput.labels(serverName=serverName).set(avgThroughput)
    else:
        handleErrorExit(response_load_full_avg_throughput.headers)
    
    response_load_full_avg_latency = requests.put(url_load_full_avg_latency, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_load_full_avg_latency.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_load_full_avg_latency.text)[Constants.FIELD_SERVERS_TRERND]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER_NAME]
            avgLatency = server_data_avg[Constants.FIELD_SERVER_TRERND][Constants.FIELD_AVG_APPLY_LATENCY][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            servers_status_utilization_status_full_load_avg_latency.labels(serverName=serverName).set(avgLatency)
    else:
        handleErrorExit(response_load_full_avg_latency.headers)

def avgTask_utilization():
    url_task_avg_memory = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-memory'
    url_task_avg_cpu = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-cpu'
    url_task_avg_disk = base_url + 'analytics/server/replicate/capacity-planning/server-utilization/avg-disk-usage'
    url_task_avg_source_target_throughput_latency = base_url + 'analytics/server/replicate/capacity-planning/change-processing-performance/avg-source-and-target-throughput-with-avg-source-and-apply-latency'

    end_time = datetime.utcnow()
    end_time_str = end_time.strftime(Constants.STR_TIME_FORMAT)
    start_time_60_minutes_ago = end_time - timedelta(minutes=60)
    start_time_60_minutes_ago_str = start_time_60_minutes_ago.strftime(Constants.STR_TIME_FORMAT)

    request_body = {
            "start": start_time_60_minutes_ago_str,
            "end": end_time_str,
            "trend_level": [
                "Hourly"
            ],
            "limit": 0
            }
    response_avg_memory = requests.put(url_task_avg_memory, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_memory.text)[Constants.FIELD_AVG_MEMORY_BY_TASK]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER]
            TaskName = server_data_avg[Constants.FIELD_TASK].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgMemory = server_data_avg[Constants.FIELD_AVG_MEMORY][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            task_utilization_status_avg_memory.labels(taskName=serverTaskName).set(avgMemory)
    else:
        response_avg_cpu(handleHealthCheck)

    response_avg_cpu = requests.put(url_task_avg_cpu, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_memory.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_cpu.text)[Constants.FIELD_AVG_AVG_CPU_BY_TASK]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER]
            TaskName = server_data_avg[Constants.FIELD_TASK].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgCPU = server_data_avg[Constants.FIELD_AVG_CPU][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            task_utilization_status_avg_cpu.labels(taskName=serverTaskName).set(avgCPU)
    else:
        handleErrorExit(response_avg_cpu.headers)


    response_avg_disk = requests.put(url_task_avg_disk, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_disk.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_disk.text)[Constants.FIELD_AVG_DISK_USAGE_BY_TASK]
        for server_data_avg in jsonData:
            serverName = server_data_avg[Constants.FIELD_SERVER]
            TaskName = server_data_avg[Constants.FIELD_TASK].replace(' ', '-')
            serverTaskName = serverName + '_' + TaskName
            avgDisk = server_data_avg[Constants.FIELD_AVG_DISK_USAGE][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE]
            task_utilization_status_avg_disk.labels(taskName=serverTaskName).set(avgDisk)
    else:
        handleErrorExit(response_avg_disk.headers)
    
    response_avg_throughput_latency = requests.put(url_task_avg_source_target_throughput_latency, headers=Header, verify=False, json=request_body)
    if handleHealthCheck(response_avg_throughput_latency.headers) == Constants.SUCCESS_CODE:
        jsonData = json.loads(response_avg_throughput_latency.text)
        task_utilization_status_avg_source_throughput.labels(taskName=Constants.FIELD_AVG_SOURCE_THROUGHPUT).set(jsonData[Constants.FIELD_AVG_SOURCE_THROUGHPUT][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE])
        task_utilization_status_avg_target_throughput.labels(taskName=Constants.FIELD_AVG_TARGET_THROUGHPUT).set(jsonData[Constants.FIELD_AVG_TARGET_THROUGHPUT][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE])
        task_utilization_status_avg_source_latency.labels(taskName=Constants.FIELD_AVG_SOURCE_LATENCY).set(jsonData[Constants.FIELD_AVG_SOURCE_LATENCY][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE])
        task_utilization_status_avg_apply_latency.labels(taskName=Constants.FIELD_AVG_APPLY_LATENCY).set(jsonData[Constants.FIELD_AVG_APPLY_LATENCY][Constants.FIRST_ELEMENT][Constants.FIELD_VALUE])
    else:
        handleErrorExit(response_avg_throughput_latency.headers)
        

if __name__ == '__main__':
    start_http_server(PORT)
    log.info('Server started on port ' + str(PORT))
    while True:
        getServerSummary()
        getTaskSummary()
        updateUtilizationStatus()
        avgMaxMachine_utilization()
        avgTask_utilization()
        time.sleep(int(SERVER_PROPERTIES['Interval_Time_in_Seconds']))    