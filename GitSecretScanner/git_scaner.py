import os 
import re
from rich.console import Console
from rich.panel import Panel
import json

base_dir = '/Users/lenar/envs/project/PyProjects/GitSecretScanner'
console = Console(highlight=False)


def load_config(config_file: str = os.path.join(base_dir, '.secret_scanner_config.json')) -> dict:
    try:
        with open(config_file, 'r') as fd:
            config = json.load(fd)
    except FileNotFoundError:
        config = {
    "ignore_dirs": [],
    "ignore_files": [],
    "patterns": {}
    }
    return config
        


def save_config(config=None, path: str = os.path.join(base_dir, '.secret_scanner_config.json')) -> None:
    if config == None:
        config = load_config()
    with open(path, 'w') as fd:
        json.dump(config, fd, indent=4)

def add_to_config(section: str, key, value=None):
    config = load_config()
    if (section == 'ignore_dirs' or section == 'ignore_files') and key not in config[section]:
        config[section].append(key)
    if section == 'patterns' and key not in config['patterns']:
        config['patterns'][key] = value
    save_config(config)




def output(path: str, line: str, sec_type: str, masked: str, c: int) -> str:
    first_line = f'total {c} fles checked \n in file: [bold green]{path}[/bold green]: {line} line, there is a [bold red]secret[/bold red] \n'
    second_line = f'[bold white]type - {sec_type}[/bold white] secret - [bold red]{masked}[/bold red]'
    final_output = Panel.fit(first_line + second_line, border_style = "bold white", title = "Statistics", title_align='center')
    return final_output

def secret_mask(secret_type: str, line: str) -> tuple:
    if len(line) <= 4:
        mask_line = '****'
        pair = (mask_line, secret_type)
    elif secret_type == 'SSH' and len(line) > 4:
        mask_line = line.split('\n')[0]
        pair = (mask_line, secret_type)
    else:
        mask = (len(line) - 4) * '*'
        new_line = line[:4]
        mask_line = new_line + mask
        pair = (mask_line, secret_type)
    return pair
    


def secret_finder(path:str) -> list:
    config = load_config()
    with open(path, 'r', encoding='utf-8') as file:
        final = []
        pat = {
            'API_key': [fr'{config['patterns']['API']}', 2, lambda v: 'AKIA' in v, 0],
            'AWS_key': [fr'{config['patterns']['AWS']}', 1, 0, 0],
            'Git_hub_token': [fr'{config['patterns']['GIT']}', 1, 0, 0],
            'SSH': [fr'{config['patterns']['SSH']}', 1, 0, re.MULTILINE],
            'generic_pas': [fr'{config['patterns']['GENERIC']}', 1, lambda s: s.startswith('gh'), re.IGNORECASE]
        }
        for line_num, line in enumerate(file, start=1):

            value = []

            for name, (regex, group_num, exc, flag) in pat.items():
                result = re.search(regex, line, flag)
                if result and not (exc and exc(result.group(group_num))):
                    type_of_sec = name
                    pair = secret_mask(type_of_sec, result.group(group_num))
                    value.append(pair)
                    final.append((path, line_num, pair))
                else:
                    continue
        return final

            

count = 0



#path = str(input('Enter file path:'))


ignore_dir = {'.git', 'node_modules', '__pycache__', 'venv', 'idea'}
ignore_dir.update(load_config()['ignore_dirs'])

def scan_directory(path):
    c = 0
    secrets = []
    for root, dirs, files in os.walk(path):

        dirs[:] = [d for d in dirs if d not in ignore_dir]

        for file in files:
            f_obj = open(f'{root}/{file}', 'r')

            try:
                f_obj.read()
            except UnicodeDecodeError:
                continue
            if file.startswith('.') and file != '.env':
                continue
            if file in load_config()['ignore_files']:
                continue

            full_path = os.path.join(root, file)

            for path, line, pair in secret_finder(full_path):
                c+=1
                masked, sec_type = pair
                secrets.append((path, line, sec_type, masked, c))
    return secrets
                
if __name__ == '__main__':
    print(base_dir)
    list_of_secrets = scan_directory(base_dir)
    if list_of_secrets:
        for path, line, sec_type, masked, c in list_of_secrets:
            console.print(output(path, line, sec_type, masked, c), justify='center')
                    
