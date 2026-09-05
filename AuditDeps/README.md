# AuditDeps
![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-brightgreen)

## DESCRIPTION

console utility for checking Python dependencies for known vulnerabilities with OSV API

## Features

* requirements.txt check
* result caching
* determination of the severity level 
    - CVSSV2
    - CVSSV3
    - CVSSV4
* output with Rich
* final statistic
* Exit code (CI/CD)

## Install

git clone https://github.com/m1cckey/AuditDeps.git
cd AuditDeps
pip install -r requirements.txt

## Using

AuditDeps/AuditDeps.py --requirements ./requirements.txt --cache ./cache.json -v(optional)

## screenshots

![Examples of program launch](screenshots/screenshot1.png)
![Examples of program launch](screenshots/screenshot2.png)
![Examples of Final stats](screenshots/final_stats.png)

## Tech Stack

Python, Requests, Rich, OSV API, Requirements-parser, Json

## Step-by-Step work

Parse the file -> request to API -> Caches -> show statistics

## Author

M1cckey https://github.com/m1cckey
