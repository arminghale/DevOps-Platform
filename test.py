import logging
import subprocess
import sys

import docker


logging.basicConfig(level=logging.DEBUG)
logging.debug(sys.version_info[:3])
if sys.version_info[:3] < (3,11,9):
    logging.debug("Python version must be >=3.11.9")

try:
    docker_client=docker.from_env()
    logging.debug(tuple(map(int, ((docker_client.version()['Version']).split(".")))))
    if tuple(map(int, ((docker_client.version()['Version']).split("."))))<(24,0,6):
        logging.debug("Docker version must be >=24.0.6")
except Exception as e:
    logging.debug(f"Docker is not installed - {e}")

nginx_check=subprocess.Popen([f'nginx -v'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
if "nginx version".casefold() not in f"{nginx_check.communicate()}".casefold():
    logging.debug("Nginx is not installed")

