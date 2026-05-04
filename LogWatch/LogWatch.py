import re

def parser_log(path: str) -> list:
    result = []
    regex = r'(?P<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<auth_user>\w+|\-) (?P<remote_user>\w+|\-) (?P<date>\[\d{1,2}\/\w{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2} [+-]\d+\]) (?P<method>\"[^\"]+\") (?P<status>\d{3}) (?P<size>\d+) (?P<http_refer>\"[^\"]+\") (?P<UA>\"[^\"]+\")'
    with open(path, 'r') as file:
        for line in file:
            match = re.search(regex, line)
            if match:
                ip = match.group('IP')
                auth_user = match.group('auth_user')
                remote_user = match.group('remote_user')
                date = match.group('date')
                method = match.group('method')
                status = match.group('status')
                size = match.group('size')
                http_refer = match.group('http_refer')
                ua = match.group('UA')
                log = {
                    "IP": ip,
                    "auth_user": auth_user,
                    "remote_user": remote_user,
                    "date": date,
                    "method": method,
                    "status": status,
                    "size": size,
                    "http_refer": http_refer,
                    "ua": ua
                }
                result.append(log)
    return result


print(parser_log('LogWatch/test_acces.log'))