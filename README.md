<div align="center">
<a href="https://gitlab.com/cossas/iochecker/-/tree/main"><img src="https://gitlab.com/cossas/iochecker/-/raw/main/IoChecker.jpg"/>

[![https://cossas-project.org/portfolio/iochecker/](https://img.shields.io/badge/website-cossas--project.org-orange)](https://cossas-project.org/portfolio/iochecker/)
[![pipeline status](https://gitlab.com/cossas/iochecker/badges/main/pipeline.svg)](https://gitlab.com/cossas/iochecker/badges/-/commits/main)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Latest Release](https://gitlab.com/cossas/iochecker/-/badges/release.svg)](https://gitlab.com/cossas/iochecker/-/releases)
</div></a>

<hr style="border:2px solid gray"> </hr>
<div align="center">
Check whether your IoC is still malicious using a dynamic and data-driven method
</div>
<hr style="border:2px solid gray"> </hr>

_All COSSAS projects are hosted on [GitLab](https://gitlab.com/cossas/iochecker/) with a push mirror to GitHub. For issues/contributions check [CONTRIBUTING](CONTRIBUTING)_ 

## What is it?
IoChecker is a Python command-line tool that ingests a C2 IP address and the date first malicious activity was detected by a CTI provider, returning whether or not the IP address is still under control of an attacker.

## Installation
To run this application successfully, please follow these steps:

1. Install Python 3.8 or higher, together with pip
2. Run `pip install -r requirements.txt` to install the necessary dependencies

or use the `Dockerfile` 

## How to use
IoChecker can be used as a standard Python program or through the supplied Dockerfile.

### Run with Python

If you have successfully installed Python 3.8 or higher and installed the required dependencies, you can use the tool by using the following arguments:

```
usage: iochecker.py [-h] [-p PORT] [-d DATE_ARRIVED] [-s {shodan,censys}] [-v] ip

IoChecker -- Provide more context for your IoCs

positional arguments:
  ip                    Specify the IP address to lookup

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Specify the port for the malicious activity on this IP
  -d DATE_ARRIVED, --date_arrived DATE_ARRIVED
                        Specify the date this IoC was listed as malicious (YYYY-MM-DD)
  -s {shodan,censys}, --source {shodan,censys}
                        Specify the datasource to use, either Shodan or Censys
  -v, --verbose         Enable verbose logging
```

### Run with Docker
This tool can also be used with the Dockerfile included in this repository. To do that, first build the container by executing:

```
docker build -t iochecker .
```

Afterward, run it by executing the following command and specify command line arguments just like with normal Python execution:

```
docker run -it iochecker [-h] [-p PORT] [-d DATE_ARRIVED] [-s {shodan,censys}] [-v] ip
```

## Examples

Suppose you are investigating the following IP: [197.89.10.236](https://feodotracker.abuse.ch/browse/host/197.89.10.236/). It was considered malicious on 2023-08-24, as it was hosting a QakBot C2 server on port 443. 
Let's find out whether that is still the case.

```
python iochecker/iochecker.py 197.89.10.236 -p 443 -d 2023-08-24 -s censys

INFO: Providing context with censys for IoC 197.89.10.236:443, known malicious on 2023-08-24
INFO: IoC 197.89.10.236 is still valid
```

## Contributing
Contributions to IoChecker are highly appreciated and more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for more information about our contributions process. 

## About
IoChecker was developed by [TNO](https://tno.nl) in close collaboration with the Dutch National Cyber Security
Centre ([NCSC](https://ncsc.nl/)) and released under [COSSAS](https://cossas-project.org).