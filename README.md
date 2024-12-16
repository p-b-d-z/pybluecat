# About

Forked from https://github.com/ForrestT/pyBluecat.git. Props to the guys at Spectrum Health for starting this... it jump started a few projects of mine.
Shame on them for leaving their company domain, IP info in public code added to PyPi.

The repo above is what PyPi was using for a long time. I've updated relevant code for Python 3.x and added some of my own functionality.

Not to be confused with https://pypi.org/project/bluecat-libraries/. This was not available when I initially started this work. I may migrate to it as time permits.

## Purpose

I do not intend to make this a public package, as Bluecat seems to be publishing their own now. I'm using it for 'research.'

Also, Bluecat wanted to charge me $300,000 for the AWS functionality as an add-on, so I wrote my own script over a weekend that does a good enough job. Enjoy.

# Docker

How to build the image:
```console
sudo docker build . --tag pybluecat:latest
```

How to run the image:
```console
sudo docker run \
  -v ~/.aws:/root/.aws \
  -e AWS_DEFAULT_PROFILE="$AWS_DEFAULT_PROFILE" \
  -e AWS_ACCESS_KEY_ID=[KEY_ID] \
  -e AWS_SECRET_ACCESS_KEY=[KEY] \
  -e BLUECAT_USER=[user] \
  -e BLUECAT_PASS=[pass] \
  -e BLUECAT_HOST=[host] \
  -e BLUECAT_CFG=[cfg name] \
  -it pybluecat:latest python3 ./scripts/sync-aws-to-bluecat.py
```

# Scripts
### jenkins.sh
This script is used by Jenkins to run the pybluecat container (or to execute locally).

### Requirements
This script is written to expect SSM parameters to be available to the workspace. You can also use `.env`. 
Each parameter matches up with a required environment variable attached to the container.
```yaml
/all/bluecat/bam_api_user
/all/bluecat/bam_api_pass
/all/bluecat/bam_api_host
/all/bluecat/bam_api_cfg
```

In addition, the Bluecat container also needs these environment variables:
```yaml
REGION
ENVIRONMENT
AWS_DEFAULT_PROFILE
```

#### Authentication
Authentication is done through volume mapping of the AWS credentials inside the docker container.
```yaml
-v ~/.aws:/root/.aws
```

### sync-aws-to-bluecat.py
```
usage: sync-aws-to-bluecat.py [-h] [--region REGION] [--environment ENVIRONMENT] [--no-ec2] [--no-fargate] [--update-bam]

Retrieve IP addresses of EC2 instances and Fargate containers

options:
  -h, --help            show this help message and exit
  --region REGION       AWS region to use (default: us-west-2)
  --environment ENVIRONMENT
                        AWS environment to use (example: production-a)
  --no-ec2              Skip EC2 instances
  --no-fargate          Skip Fargate containers
  --update-bam          Update Bluecat Address Manager
```
#### Environment Variables

Bluecat Address Manager:
- BLUECAT_HOST
- BLUECAT_CFG
- BLUECAT_USER
- BLUECAT_PASS

AWS:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- REGION

#### Example usage

List AWS Private IPs for us-west-2:
```
python3 sync-aws-to-bluecat.py --region us-west-2
```
List AWS Private IPs for us-west-2 and update Bluecat records:
```
python3 sync-aws-to-bluecat.py --update-bam
```

List AWS Private IPs for eu-west-2 production-a and update Bluecat records:
```
python3 sync-aws-to-bluecat.py --region us-west-2 --environment production-a --update-bam
```

# Bluecat CLI

You can also just use the CLI scripts interactively (use -h, --help)

```bash
bluecat --help

    usage: Bluecat CLI Tool [-h] {static,dhcp,search} ...

    optional arguments:
      -h, --help            show this help message and exit

    Subcommands:
      {static,dhcp,search}  subparsers command help
        static              static IP record manipulation
        dhcp                dhcp IP record manipulation
        search              search BAM for Objects

# Search for a hostname
bluecat search --name <hostname> 

# Search for a DNS name
bluecat search --dns <hostname>

# Search for a MAC address
bluecat search --mac <macAddress>

# Create a DHCP reservation
bluecat dhcp create <hostname> <mac> --network <networkAddress>

# Delete a STATIC IP reservation
bluecat static delete <ipAddress>

# Bluecat BAM API Wrapper #

## Installation ##

You can clone the repo, change to the top-level directory (with the setup.py file) and use pip to install the local files in "editable" mode (-e).

```bash
git clone https://github.com/p-b-d-z/pybluecat.git
cd pybluecat
pip install --user .
```
- - - -
## How to Use ##

The library can be used within Python3 applications.

```python
import pybluecat

bam = pybluecat.BAM(hostname, username, password, config_name)  

network_obj = bam.get_network('10.97.12.0')

ip_obj = bam.get_ip_address('10.97.12.101')

bam.logout()
```
In an interactive python interpreter, use help() to play with the available methods
```python
>>> from pybluecat import BAM
>>> help(BAM)
```
