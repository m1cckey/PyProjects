import re
import pandas as pd
import numpy as np
from datetime import datetime


def parser_log(path: str) -> list:
    result = []
    regex = r'(?P<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<auth_user>\w+|\-) (?P<remote_user>\w+|\-) (?P<date>\[\d{1,2}\/\w{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2} [+-]\d+\]) (?P<full_method>\"[^\"]+\") (?P<status>\d{3}) (?P<size>\d+) (?P<http_refer>\"[^\"]+\") (?P<UA>\"[^\"]+\")'
    with open(path, 'r') as file:
        for line in file:
            match = re.search(regex, line)
            if match:
                ip = match.group('IP')
                auth_user = match.group('auth_user')
                remote_user = match.group('remote_user')
                dt = match.group('date')
                dt = datetime.strptime(dt, "[%d/%b/%Y:%H:%M:%S %z]")
                date = pd.to_datetime(dt)
                full_method = match.group('full_method')
                status = match.group('status')
                size = match.group('size')
                http_refer = match.group('http_refer')
                ua = match.group('UA')
                log = {
                    "IP": ip,
                    "auth_user": auth_user,
                    "remote_user": remote_user,
                    "date": date,
                    "full_method": full_method,
                    "status": int(status),
                    "size": size,
                    "http_refer": http_refer,
                    "UA": ua
                }
                result.append(log)
    return result




def detect_sql_injection(data: list) -> list:
    regex = r'(?P<pattern>(OR 1=1|\' OR |UNION SELECT|DROP TABLE|DELETE|INSERT|UPDATE|\-\-|\/\*))'
    result = []
    for item  in data:
        match = re.search(regex, item['full_method'], re.IGNORECASE)
        if match:
            triplet = {"Pattern": match.group('pattern'),
                        "Method": item['full_method'],
                        "IP": item['IP'], 
                        "Description": 'SQL Injection detected'}
            result.append(triplet)
    return result


def detect_sus_ua(data: list) -> list:
    regex = r'(?P<pattern>(sqlmap|nikto|gobuster|dirbuster|dirb|nmap|curl|wget|python-requests|python-urllib|wpscan|burp|acunetix|nessus|metasploit|hydra|zgrab|masscan))'
    result = []
    for item  in data:
        match = re.search(regex, item['UA'], re.IGNORECASE)
        if match:
            triplet = {"IP": item['IP'],
                        "Pattern": match.group('pattern'),
                        "Description": 'Suspicious UA',
                        "Method": item['full_method']}
                    
            result.append(triplet)
    return result

def brute_force(data: list, threshhold: int = 5) -> list:
    df = pd.DataFrame(data)
    df = df[df['status'].isin([401, 403])]
    invalid = df.groupby('IP').filter(lambda x: x['status'].count() >= threshhold)
    invalid = invalid.drop_duplicates(subset=['IP'])
    attemps = invalid['IP'].size
    invalid = invalid.to_dict('records')
    for elems in invalid:
        elems['attemps'] = attemps
        elems['description'] = 'Brute force detected'
    return invalid



def detect_scanning(data: list, treshhold: int = 5) -> list:
    df = pd.DataFrame(data)
    df = df[df['status'].isin([404])]
    invalid = df.groupby('IP').filter(lambda v: v['full_method'].nunique() >= treshhold)
    invalid = invalid.groupby('IP').filter(lambda x: x['status'].count() >= treshhold)
    invalid = invalid.drop_duplicates(subset=['IP'])
    attemps = invalid['IP'].size
    invalid = invalid.to_dict('records')
    for elems in invalid:
        elems['attemps'] = attemps
        elems['description'] = 'Scanning detected'
    return invalid   


def detect_xss(data: list) -> list:
    result = []
    regex = r'(?P<pattern>(on\w+\s=[^\"]*)|(<.+>)|(javascript))'
    for line in data:
        match = re.search(regex, line['full_method'], re.IGNORECASE)
        if match:
            triplet = {
                "Patern": match.group('pattern'),
                "IP": line['IP'],
                "full method": line['full_method'],
                "description": 'XSS attack detected'
            }
            result.append(triplet)
    return result



def detect_spike(data: list) -> list:
    res =[]
    df = pd.DataFrame(data)
    df = df[df['status'].isin([500, 502, 503])]
    df['date'] = pd.to_datetime(df['date'])
    df['round_time'] = df['date'].dt.floor('min')
    invalid = df.groupby(['round_time']).size()
    arr = np.array(invalid)
    mn = np.mean(arr)
    st = np.std(arr)
    z_score = (arr-mn)/st
    mask = z_score > 2
    outliers = invalid[mask]
    for time, count in outliers.items():
        dict_of_spikes ={
            "time": str(time),
            "Errors": count,
            "Description": "Error spike detected"
        }
    
        res.append(dict_of_spikes)
    return res

print(detect_sql_injection(parser_log('LogWatch/test_acces.log')))
print('-'*20)
print(detect_sus_ua(parser_log('LogWatch/test_acces.log')))
print('-'*20)
print(brute_force(parser_log('LogWatch/test_acces.log')))
print('-'*20)
print(detect_scanning(parser_log('LogWatch/test_acces.log')))
print('-'*20)
print(detect_xss(parser_log('LogWatch/test_acces.log')))
print('-'*20)
print(detect_spike(parser_log('LogWatch/test_acces.log')))

