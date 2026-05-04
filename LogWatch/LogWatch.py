import re

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
                    "status": status,
                    "size": size,
                    "http_refer": http_refer,
                    "ua": ua
                }
                result.append(log)
    return result




def detect_sql_injection(data: list):
    regex = r'.+ (?P<pattern>(OR \'\d\'=\'\d)|(SELECT|DROP|DELETE|INSERT|UPDATE)|(\-\-)|(\/\*))'
    result = []
    for item  in data:
        match = re.search(regex, item['full_method'], re.IGNORECASE)
        if match:
            triplet = (match.group('pattern'), item['full_method'], item['IP'], 'SQL Injection detected')
            result.append(triplet)
    return result


sql = detect_sql_injection(parser_log('LogWatch/test_acces.log'))
for pattern, full_method, ip, reason in sql:
    print(f'pattern: {pattern}\nmethod: {full_method}\nIP: {ip}\nreason: {reason}') 
