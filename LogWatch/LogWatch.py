import re
import pathlib
import argparse
import logging
import pandas as pd
import numpy as np
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
import matplotlib.pyplot as plt
console = Console(highlight=False)

class guard:

    def __init__(self, log_path):
        self.log_path = log_path
        logging.debug(f'{self.log_path}')
        self.parsed_file = self.parser_log(self.log_path)
        logging.debug(f'{self.parsed_file}')
        self.sql = self.detect_sql_injection(self.parsed_file) 
        logging.debug(f'{self.sql}')
        self.sus_ua = self.detect_sus_ua(self.parsed_file)
        logging.debug(f'{self.sus_ua}')
        self.br_force = self.brute_force(self.parsed_file) 
        logging.debug(f'{self.br_force}')
        self.scanners = self.detect_scanning(self.parsed_file)
        logging.debug(f'{self.scanners}')
        self.xss_attack = self.detect_xss(self.parsed_file)
        logging.debug(f'{self.xss_attack}')
        self.spikes = self.detect_spike(self.parsed_file)
        logging.debug(f'{self.spikes}')
        self.data = [*self.sql, *self.sus_ua, *self.br_force, *self.scanners, *self.xss_attack, *self.spikes]
        logging.debug(f'{self.data}')
        self.total_req = 0
        self.all_ips = []
        self.total_sus_req = 0
        self.unic_sus_ip = []
        self.anomalies_count = {
                        'SQL Injection detected': 0,
                        'Sus UA': 0,
                        'Brute force detected': 0,
                        'Scanning detected': 0,
                        'XSS attack detected': 0,
                        'Error spike detected': 0
                        }


    def display_report(self):
        with open(self.log_path) as f:
            for line in f:
                logging.info(f'{line}')
                if len(line) > 1:
                    self.total_req += 1
                    ips = line.split(' ')
                    self.all_ips.append(ips)
            for elem in self.data:
                self.total_sus_req += 1
                for key, value in elem.items():
                    if key == 'IP':
                        self.unic_sus_ip.append(value)
                    if key == 'Description':
                        logging.debug(f'{value}')
                        logging.debug(f'{self.anomalies_count[value]}')
                        self.anomalies_count[value] += 1
        return self.total_req, len(tuple(self.unic_sus_ip)), self.anomalies_count, len(tuple(self.all_ips))



                    

        
    def parser_log(self, path: str) -> list:
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




    def detect_sql_injection(self, data: list) -> list:
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


    def detect_sus_ua(self, data: list) -> list:
        regex = r'(?P<pattern>(sqlmap|nikto|gobuster|dirbuster|dirb|nmap|curl|wget|python-requests|python-urllib|wpscan|burp|acunetix|nessus|metasploit|hydra|zgrab|masscan))'
        result = []
        for item  in data:
            match = re.search(regex, item['UA'], re.IGNORECASE)
            if match:
                triplet = {"IP": item['IP'],
                            "Pattern": match.group('pattern'),
                            "Description": 'Sus UA',
                            "Method": item['full_method']}
                        
                result.append(triplet)
        return result

    def brute_force(self, data: list, threshhold: int = 5) -> list:
        df = pd.DataFrame(data)
        df = df[df['status'].isin([401, 403])]
        invalid = df.groupby('IP').filter(lambda x: x['status'].count() >= threshhold)
        invalid = invalid.drop_duplicates(subset=['IP'])
        attemps = invalid['IP'].size
        invalid = invalid.to_dict('records')
        for elems in invalid:
            elems['attemps'] = attemps
            elems['Description'] = 'Brute force detected'
        return invalid



    def detect_scanning(self, data: list, treshhold: int = 5) -> list:
        df = pd.DataFrame(data)
        df = df[df['status'].isin([404])]
        invalid = df.groupby('IP').filter(lambda v: v['full_method'].nunique() >= treshhold)
        invalid = invalid.groupby('IP').filter(lambda x: x['status'].count() >= treshhold)
        invalid = invalid.drop_duplicates(subset=['IP'])
        attemps = invalid['IP'].size
        invalid = invalid.to_dict('records')
        for elems in invalid:
            elems['attemps'] = attemps
            elems['Description'] = 'Scanning detected'
        return invalid   


    def detect_xss(self, data: list) -> list:
        result = []
        regex = r'(?P<pattern>(on\w+\s=[^\"]*)|(<.+>)|(javascript))'
        for line in data:
            match = re.search(regex, line['full_method'], re.IGNORECASE)
            if match:
                triplet = {
                    "Patern": match.group('pattern'),
                    "IP": line['IP'],
                    "full method": line['full_method'],
                    "Description": 'XSS attack detected'
                }
                result.append(triplet)
        return result



    def detect_spike(self, data: list) -> list:
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





    def output(self, data) -> str:
        total_requests, unic_sus_ip, anomalies_count, all_ips = data
        first_line = f'[bold white]Total requests: {total_requests}[/bold white]\n'
        second_line = f'[bold white]Total unic IPs: {all_ips}[/bold white]\n'
        third_line = f'[bold yellow]IPs with anomalies: {unic_sus_ip}[/bold yellow]\n'
        other_lines = ' '.join(list((f'{key}: {value}\n' for key, value in anomalies_count.items())))
        return Panel.fit(str(first_line) + str(second_line) + str(third_line) + f'[bold red]{str(other_lines)}[/bold red]', border_style = "bold white", title = "Statistics", title_align='center')


    def show_stat(self):
        console.print(self.output(self.display_report()), justify='center')

    

               




    def pie_graphics(self) -> None:
        sizes = []
        labels = []
        colors = ["#FFB3B3","#9ac9f8","#9bff9b", "#9994FF", "#FEFEA1", "#FF94CA", "#89f8f3"]

        df = pd.DataFrame(self.parsed_file)
        df = df.groupby(['status']).size()
        for key, value in dict(df).items():
            key = str(key)
            value = int(value)
            sizes.append(value)
            labels.append(key)
        plt.pie(sizes, colors=colors, labels=labels, startangle=140, autopct='%1.f%%', labeldistance=10)
        plt.legend(bbox_to_anchor = (-0.16, 0.45, 0.25, 0.25), loc = 'best', labels = labels)
        plt.axis('equal')
        plt.title('Error Distribution')
        plt.show()

  

    def line_graphics(self) -> None:
        ax = []
        oy = []
        df = pd.DataFrame(self.parsed_file)
        df = df[df['status'].isin([500, 502, 503])]
        df['round_time'] = df['date'].dt.floor('min')
        df = df.groupby(['round_time']).size()
        for x, y in dict(df).items():
            ax.append(x)
            oy.append(y)
        plt.plot(ax,oy)
        plt.title('5XX Eroors Distribution')
        plt.xlabel('Time')
        plt.ylabel('Amount')
        plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--logs', required=True, help='path to acces.log')
    parser.add_argument('-v', '--verbose', action='store_true', help='debug mode')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    acces_log_path = pathlib.Path(args.logs)
    guardian = guard(acces_log_path)
    guardian.show_stat()
