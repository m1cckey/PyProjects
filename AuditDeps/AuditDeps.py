import requirements as rq
import json as js
import requests
import time
import sys
from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)


def vuln_stats(package: list) -> tuple:
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
                    all_severity.append(final_severity_V3_V4(element["score"]))
                elif element["type"] == "CVSS_V2":
                    all_severity.append(final_severity_V2(element["score"]))
                else:
                    all_severity.append('UNKNOWN')
    return (count_vul, vul_id, all_severity)


def final_stats(total: int, vuln: int, clean: int) -> str:
    line = '=' * 20
    head = f'[bold cyan]{line}\nFINAL STATISTICS\n{line}[/bold cyan]\n'
    first_line = f'[bold blue]Total packages checked: {total}[/bold blue]\n'
    second_line = f'[bold red]With vulnerabilities: {vuln}[/bold red]\n'
    third_line = f'[bold green]clean: {clean}[/bold green]\n[bold cyan]{line}[/bold cyan]\n'
    return f'{head}{first_line}{second_line}{third_line}'



def vuln_result(name: str, data: dict) -> str:
    if not data:
        count = 0
        final = ''
        color_name = f'[bold green]{name}[/bold green]'
    else:
        count, ids, sev = vuln_stats(data['vulns'])
        temp = []
        for i in range(count):
            id_and_sev = f'{ids[i]} - has {colored(sev[i])} level of severity'
            temp.append(id_and_sev)
        final = ', '.join(temp)
        color_name = f'[bold red]{name}[/bold red]'
    
    return f'{color_name} has {count} vulnerability: {final}'


def colored(severity: str) -> str:
    if severity == 'CRITICAL' or severity == 'HIGH':
        color = f'[bold red]{severity}[/bold red]'
    elif severity == 'MEDIUM':
       color = f'[bold yellow]{severity}[/bold yellow]'
    elif severity == 'LOW':
        color = f'[bold green]{severity}[/bold green]'
    else:
        color = f'[bold white]{severity}[/bold white]'
    return color


def final_severity_V3_V4(score: str) -> str:
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


def final_severity_V2(score: str) -> str:
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



try:
    with open('AuditDeps/.audit_cache.json', 'r') as f:
        cache = js.load(f)      
except FileNotFoundError:
        cache = {}



pack =[]
with open('AuditDeps/requirements.txt', 'r') as fd:
    for req in rq.parse(fd):
        ver = req.specs
        for el in ver:
            if el[0] == '==' or el[0] == '>=':
                pair = (req.name, el[1])
                pack.append(pair)

total = 0
without_vuln = 0
api_url = "https://api.osv.dev/v1/query"
for name, version in pack:
    total += 1
    key = f'{name}=={version}'
    if key in cache:
        data = cache[key]
        if data == {}:
            without_vuln +=1
    else:
        payload = {
            "package": {
                "name": name,
                "ecosystem": "PyPI"
            },
            "version": version,               
        }
        response = requests.post(api_url, json = payload)
        time.sleep(0.5)
        if response.status_code == 200:
            data = response.json()
            if data == {}:
                without_vuln += 1
            cache[key] = data
        else:
            print(f'Something went wrong {response.status_code}')
            continue
        

    console.print('[reset]')
    console.print(vuln_result(name, data),)

console.print(Panel.fit(final_stats(total, total-without_vuln, without_vuln)), justify='center')

with open('AuditDeps/.audit_cache.json', 'w') as file:
    js.dump(cache, file, indent = 4, ensure_ascii=False)


if total - without_vuln > 0:
    warning = Panel.fit("[bold red]VULNERABILITIES FOUND[/bold red]", border_style="red")
    console.print(warning, justify='center')
    sys.exit(1)
else:
    sys.exit(0)