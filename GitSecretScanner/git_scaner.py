import os 
import re
from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)


def output(path: str, line: str, sec_type: str, masked: str, c: int) -> str:
    first_line = f'total {c} fles checked \n in file: [bold green]{path}[/bold green]: {line} line, there is a [bold red]secret[/bold red] \n'
    second_line = f'[bold white]type - {sec_type}[/bold white] secret - [bold red]{masked}[/bold red]'
    final_output = Panel.fit(first_line + second_line, border_style = "bold white", title = "Statistics", title_align='center')
    return final_output

def secret_mask(secret_type: str, line: str) -> tuple:
    if len(line) <= 4:
        mask_line = '****'
        pair = (mask_line, secret_type)
    elif (secret_type == 'GIT' or secret_type == 'AWS' or secret_type == 'PASSWORD' or secret_type == 'API') and len(line) > 4:
        mask = (len(line) - 5) * '*'
        new_line = line[:4]
        mask_line = new_line + mask
        pair = (mask_line, secret_type)
    elif secret_type == 'SSH' and len(line) > 4:
        mask_line = line.split('\n')[0]
        pair = (mask_line, secret_type)
    return pair
    


def secret_finder(path:str) -> list:
    with open(path, 'r', encoding='utf-8') as file:
        final = []
        
        API_key = r'([0-9A-Z]+_KEY\w*)\s?[:=]\s?[\'\"]?([0-9a-zA-Z\s\._-]+)[\'\"]?'
        AWS_key = r'(AKIA[0-9a-zA-z]{16})'
        Git_hub_token = r'(gh[pousr]_[a-zA-Z0-9]{36})'
        SSH = r'-----BEGIN.+-----'
        generic_pas = r'(?:password|passwd|token)\s?[:=]\s?[\'\"]?([0-9a-zA-Z\s\._-]+)[\'\"]?'

        for line_num, line in enumerate(file, start=1):

            value = []

            result_api = re.search(API_key, line)
            result_aws = re.search(AWS_key, line)
            result_git = re.search(Git_hub_token, line)
            result_ssh = re.search(SSH, line, re.MULTILINE)
            result_password = re.search(generic_pas, line, re.IGNORECASE)

            if result_api and not ('AKIA' in result_api.group(2)):
                type_of_sec = 'API'
                pair = secret_mask(type_of_sec, result_api.group(2))
                value.append(pair)
                final.append((path, line_num, pair))

            if result_aws:
                type_of_sec = 'AWS'
                pair = secret_mask(type_of_sec, result_aws.group(1))
                value.append(pair)
                final.append((path, line_num, pair))

            if result_git:
                type_of_sec = 'GIT'
                pair = secret_mask(type_of_sec, result_git.group(1))
                value.append(pair)
                final.append((path, line_num, pair))

            if result_ssh:
                type_of_sec = 'SSH'
                pair = secret_mask(type_of_sec, result_ssh.group())
                value.append(pair)
                final.append((path, line_num, pair))

            if result_password and not (result_password.group(1).startswith('gh')):
                type_of_sec = 'PASSWORD'
                pair = secret_mask(type_of_sec, result_password.group(1))
                final.append((path, line_num, pair))
            
    return final

count = 0
c = 0

path = 'GitSecretScanner'
#path = str(input('Enter file path:'))


ignore_dir = {'.git', 'node_modules', '__pycache__', 'venv', 'idea'}

for root, dirs, files in os.walk(path):

    for dir in dirs:
        if dir in ignore_dir:
            continue

    for file in files:
        f_obj = open(f'{root}/{file}', 'r')

        try:
            f_obj.read()
        except UnicodeDecodeError:
            continue

        if file.startswith('.') and file != '.env' or file == 'git_scaner.py':
            continue

        full_path = os.path.join(root, file)
        c += 1

        for path, line, pair in secret_finder(full_path):
            masked, sec_type = pair
            console.print(output(path, line, sec_type, masked, c), justify='center')

