# LogWatch
![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-brightgreen)


## Description

console utility for checking anomalies in website access log

## Features
* Different anomalies type 
    - SQL injections
    - Suspect UA
    - XSS attacks
    - Scanners
    - Brute Force
    - Error spikes
* colorful output

## Install

* Clone repository
 - git clone https://github.com/m1cckey/PyProjects.git
 - cd PyProjects/LogWatch

* crating venv
    - python -m venv venv
    - source venv/bin/activate   # Mac/Linux

* install requirements
    - pip install -r requirements.txt

## Using

python LogWatch.py


## Screenshots

![Examples of statistics](scr1.png)
![Examples of pie graphic](scr2.png)
![Examples of line graphic](scr3.png)


## Tech Stack

Python, Matplotlib, Numpy, Rich


## Step-by-Step Work

parse access log -> collecting anomalies -> statistic -> graphics


## Author

M1cckey https://github.com/m1cckey

