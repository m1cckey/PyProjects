import re
import pandas as pd


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
                date = match.group('date')
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
                        "Description": 'Suspicious UA'}
            result.append(triplet)
    return result

def brute_force(data: list, threshhold = 5) -> list:
    df = pd.DataFrame(data)
    df = df[df['status'].isin([401, 403])]
    invalid = df.groupby('IP').filter(lambda x: x['status'].count() >= threshhold)
    atemps = invalid['IP'].size
    invalid = invalid.drop_duplicates(subset=['IP'])
    invalid = invalid.to_dict('records')
    for elems in invalid:
        elems['atemps'] = atemps
        elems['description'] = 'Brute force detected'
    return invalid

#TODO: detect_scsannig deetct_xss detect_spike



b = detect_sql_injection(parser_log('LogWatch/test_acces.log'))
for el in b:
    for k, v in el.items():
        print(f'{k}: {v}')
s = brute_force(parser_log('LogWatch/test_acces.log'))
print('-'*20)
for elem in s:
    for a, c in elem.items():
        print(f'{a}: {c}')



print(parser_log('LogWatch/test_acces.log')[3]['full_method'])
