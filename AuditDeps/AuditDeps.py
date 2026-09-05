import requirements
import json
import requests
import time
import sys
import argparse
import pathlib
import logging
from rich.console import Console
from rich.panel import Panel




class AuditScanner:
    def __init__(self, file_path, cache_path):
        self.file_path = file_path
        self.cache_path = cache_path
        self.pack =[]
        self.total = 0
        self.without_vuln = 0
        self.cache = {}

    def load_cache(self):
        try:
            with open(self.cache_path, 'r') as f:
                self.cache = json.load(f)    
                logging.debug(f'cache found.\n{len(self.cache)} elements')
        except (FileNotFoundError, json.decoder.JSONDecodeError):
                logging.debug('no cache found, initializing empty cache')
                self.cache = {}
        return None
    
    
    
    def create_pack(self):
        with open(self.file_path, 'r') as fd:
            for req in requirements.parse(fd):
                ver = req.specs
                for el in ver:
                    if el[0] == '==' or el[0] == '>=':
                        pair = (req.name, el[1])
                        self.pack.append(pair)
        logging.debug(f'parsing complete {len(self.pack)} elements found')
        return None

    

    def create_resp(self):
        logging.info('start checking')
        api_url = "https://api.osv.dev/v1/query"
        for name, version in self.pack:
            self.total += 1
            key = f'{name}=={version}'
            if key in self.cache:
                data = self.cache[key]
                logging.info('information was taken from cache')
                self.output(name, data)  
                if data == {}:
                    self.without_vuln +=1
            else:
                payload = {
                    "package": {
                        "name": name,
                        "ecosystem": "PyPI"
                    },
                    "version": version,               
                }
                for attemp in range(3):
                    try:
                        response = requests.post(api_url, json = payload)
                        
                        logging.info(f'Response to OSV created')
                        time.sleep(0.5)
                        response.raise_for_status()
                        logging.info('response successful and added to the cache')
                        data = response.json()
                        self.output(name, data)
                        if data == {}:
                            self.without_vuln += 1
                        self.cache[key] = data
                        break
                    except requests.exceptions.RequestException:
                        logging.warning('request failed, retrying...')
                        if attemp == 2:
                            logging.error('all attemps failed')
                
        console.print(Panel.fit(self.final_stats(self.total, self.total-self.without_vuln, self.without_vuln)), justify='center')
        with open(self.cache_path, 'w') as file:
            json.dump(self.cache, file, indent = 4, ensure_ascii=False)
                


    def vuln_stats(self, package) -> tuple:
        count_vul = 0
        vul_id = []
        all_severity = []
        for el in package:
            count_vul+=1
            vul_id.append(el['id'])
            vul_sev = el.get('severity', '')
            if not vul_sev:
                vul_sev = el.get('database_specific', {}).get('severity', 'UNKNOWN')
                if vul_sev == 'MODERATE':
                    vul_sev = 'MEDIUM'
                all_severity.append(vul_sev)
            else:
                for element in vul_sev:
                    if element["type"] == "CVSS_V3" or element["type"] == "CVSS_V4":
                        all_severity.append(self.final_severity_V3_V4(element["score"]))
                    elif element["type"] == "CVSS_V2":
                        all_severity.append(self.final_severity_V2(element["score"]))
                    else:
                        all_severity.append('UNKNOWN')
        return (count_vul, vul_id, all_severity)

    
    def vuln_result(self, name: str, data: dict) -> str:
        if not data:
            count = 0
            final = ''
            color_name = f'[bold green]{name}[/bold green]'
        else:
            count, ids, sev = self.vuln_stats(data['vulns'])
            temp = []
            for i in range(count):
                id_and_sev = f'{ids[i]} - has {self.colored(sev[i])} level of severity'
                temp.append(id_and_sev)
            final = ', '.join(temp)
            color_name = f'[bold red]{name}[/bold red]'
        
        return f'{color_name} has {count} vulnerability: {final}\n'

    

    def final_stats(self, total: int, vuln: int, clean: int) -> str:
            line = '=' * 20
            head = f'[bold cyan]{line}\nFINAL STATISTICS\n{line}[/bold cyan]\n'
            first_line = f'[bold blue]Total packages checked: {total}[/bold blue]\n'
            second_line = f'[bold red]With vulnerabilities: {vuln}[/bold red]\n'
            third_line = f'[bold green]clean: {clean}[/bold green]\n[bold cyan]{line}[/bold cyan]\n'
            return f'{head}{first_line}{second_line}{third_line}'



    def colored(self, severity: str) -> str:
        if severity == 'CRITICAL' or severity == 'HIGH':
            color = f'[bold red]{severity}[/bold red]'
        elif severity == 'MEDIUM':
            color = f'[bold yellow]{severity}[/bold yellow]'
        elif severity == 'LOW':
            color = f'[bold green]{severity}[/bold green]'
        else:
            color = f'[bold white]{severity}[/bold white]'
        return color



    
    def final_severity_V3_V4(self, score: str) -> str:
            list_of_score = score.split('/')
            all_levels = []
            for element in list_of_score:
                if element.startswith('C:') or element.startswith('A:') or element.startswith('I:') or element.startswith('VC:') or element.startswith('VA:') or element.startswith('VI:'):
                    idx = element.find(':')
                    risk = element[idx+1]
                    all_levels.append(risk)
            if all_levels.count('H') > 1:
                level = 'CRITICAL'
            elif all_levels.count('H') == 1:
                level = 'HIGH'
            elif all_levels.count('L') >= 1 and all_levels.count('H') == 0:
                level = 'MEDIUM'
            elif all_levels.count('N') >= 1 and all_levels.count('H') == 0 and all_levels.count('L') == 0:
                level = 'LOW' 
            else:
                level = 'UNKNOWN'
            return level




    def final_severity_V2(self, score: str) -> str:
            list_of_score = score.split('/')
            all_levels = []
            for element in list_of_score:
                if element.startswith('C:') or element.startswith('A:') or element.startswith('I:'):
                    idx = element.find(':')
                    risk = element[idx+1]
                    all_levels.append(risk)
            if all_levels.count('C') > 1:
                level = 'CRITICAL'
            elif all_levels.count('C') == 1:
                level = 'HIGH'
            elif all_levels.count('P') >= 1 and all_levels.count('C') == 0:
                level = 'MEDIUM'
            elif all_levels.count('N') >= 1 and all_levels.count('C') == 0 and all_levels.count('P') == 0:
                level = 'LOW' 
            else:
                level = 'UNKNOWN'
            return level


    def output(self, name, data):
        console.print('[reset]')
        console.print(self.vuln_result(name, data))
        



if __name__ == '__main__':

    

    console = Console(highlight=False)


    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--requirements', required=True, help='path to reqs')
    parser.add_argument('-c', '--cache', default='.audit_cache.json', help='path to cache')
    parser.add_argument('-v', '--verbose', action='store_true', help='debug mode')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    file_path = pathlib.Path(args.requirements)
    cache_path = pathlib.Path(args.cache)

    scanner = AuditScanner(file_path, cache_path)
    scanner.load_cache()
    scanner.create_pack()
    scanner.create_resp()
    
  
    if scanner.total - scanner.without_vuln > 0:
        warning = Panel.fit("[bold red]VULNERABILITIES FOUND[/bold red]", border_style="red")
        console.print(warning, justify='center')
        sys.exit(1)
    else:
        sys.exit(0)
