# GitSecretScanner
![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-brightgreen)

## DESCRIPTION

console utility and git hub pre-commit hook to search for passwords secrets and various keys

## Features

* Recursive crawling of all files and folders in the directory
* Ability to skip folders and files when traversing
* Custom configurations
    - add to config
    - save config
    - load config
* output with Rich
* Exit code (CI/CD)

## Install

* Clone repository
 - git clone https://github.com/m1cckey/PyProjects.git
 - cd PyProjects/GitSecretScanner

* crating venv
    -python -m venv venv
    -source venv/bin/activate   # Mac/Linux

* install requirements
    -pip install -r requirements.txt

* install Git hook (optional)
    - cp pre-commit ../.git/hooks/pre-commit
    - chmod +x ../.git/hooks/pre-commit
## Using

python git_scaner.py or python git_scaner.py /Path/to/project

## screenshots

![Examples of program launch from git_scanner.py](screenshot3.png)
![Examples of hook launch](screenshot4.png)


## Tech Stack

Python, Rich, Json

## Step-by-Step work

Recursive crawl -> checking for secrets -> show statistics

## Author

M1cckey https://github.com/m1cckey
