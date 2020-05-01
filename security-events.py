import requests
import sys
import json
import os
import time
import logging
import tabulate
import yaml
import pandas as pd
from pandas import ExcelWriter
from logging.handlers import TimedRotatingFileHandler

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

def get_logger(logfile, level):
    '''
    Create a logger
    '''
    if logfile is not None:

        '''
        Create the log directory if it doesn't exist
        '''

        fldr = os.path.dirname(logfile)
        if not os.path.exists(fldr):
            os.makedirs(fldr)

        logger = logging.getLogger()
        logger.setLevel(level)
 
        log_format = '%(asctime)s | %(levelname)-8s | %(funcName)-20s | %(lineno)-3d | %(message)s'
        formatter = logging.Formatter(log_format)
 
        file_handler = TimedRotatingFileHandler(logfile, when='midnight', backupCount=7)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

        return logger

    return None


class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            if logger is not None:
                logger.error("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None

if __name__ == '__main__':

    try:

        log_level = logging.DEBUG
        logger = get_logger("log/security_events.txt", log_level)

        try: 
            start_date = input("Please enter start date(YYYY-MM-DD): ")
            time.strptime(start_date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect start data format, please enter in YYYY-MM-DD") 
        try:    
            end_date = input("Please enter end date(YYYY-MM-DD): ")
            time.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect end data format, please enter in YYYY-MM-DD")         

        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,username,password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice"%(vmanage_host,vmanage_port)

        # Get security events

        # open excel file 
        filename = 'Security Events %s.xlsx'%time.strftime("%Y-%m-%d")
        writer = ExcelWriter(filename)

        api_url = "/event"

        payload = {
                            "query": {
                                "condition": "AND",
                                "rules": [
                                {
                                    "value": [
                                              start_date+"T00:00:00 UTC",
                                              end_date+"T00:00:00 UTC" 
                                             ],
                                    "field": "entry_time",
                                    "type": "date",
                                    "operator": "between"
                                },
                                {
                                    "value": [
                                                "utd-ips-alert",
                                                "utd-update",
                                                "utd-file-reputation-alert",
                                                "utd-file-reputation-status-event",
                                                "utd-file-analysis-status-event",
                                                "utd-version-mismatch",
                                                "utd-file-reputation-retrospective-alert",
                                                "utd-sessions-max",
                                                "utd-engine-status",
                                                "utd-file-analysis-file-upload-state",
                                                "utd-notification"
                                             ],
                                    "field": "eventname",
                                    "type": "string",
                                    "operator": "in"
                                }
                                ]
                            }
                  }

        url = base_url + api_url

        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

        if response.status_code == 200:

            security_events = response.json()["data"]
            
            date_list = list()
            hostname_list = list()
            sysip_list = list()
            eventname_list = list()
            sevlevel_list = list()
            eventdetails_list = list()

            for item in security_events:

                date_list.append(time.strftime('%m/%d/%Y',  time.gmtime(item['entry_time']/1000.)))
                hostname_list.append(item['host_name'])
                sysip_list.append(item['system_ip'])
                eventname_list.append(item['eventname'])
                sevlevel_list.append(item['severity_level'])
                eventdetails_list.append(item['details'])

            excel_content = dict()
            excel_content["Date"] = date_list
            excel_content["Host name"] = hostname_list
            excel_content["System IP"] = sysip_list
            excel_content["Event Name"] = eventname_list
            excel_content["Severity level"] = sevlevel_list
            excel_content["Event Details"] = eventdetails_list

            df = pd.DataFrame(excel_content)
            df.to_excel(writer, "Security_Events" ,index=False)
            
            writer.save()
            print("\nCreated security events file %s"%filename)
                
        else:
            if logger is not None:
                logger.error("Failed to retrieve Security events\n")

    except Exception as e:
        print('Exception line number: {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)