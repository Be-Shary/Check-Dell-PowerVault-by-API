import requests
import sys
import hashlib
import argparse
from argparse import RawTextHelpFormatter, SUPPRESS

# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_sessionkey(hostname, username, password):
    try:
        login = str(username) + "_" + str(password)
        url = "https://" + str(hostname) + "/api/login/"
        auth_string = hashlib.sha256(login).hexdigest()
        headers = {"datatype":"json"}
        response = requests.get(url + auth_string, headers=headers, verify=False )
        data = response.json()
        sessionKey = data["status"][0]["response"]
        return sessionKey
    except:
        print("UNKNOWN - Unexpected error: " + str(sys.exc_info()))
        sys.exit(3)


def get_data(url, session_key):
    try:
        headers = {"sessionKey": session_key, "datatype": "json"}
        response = requests.get(url, headers=headers, verify=False)
        code = (response.status_code)
        if code == 206 or code == 200:
            data = response.json()
            return data
        else:
            sys.exit(3)
    except requests.exceptions.ConnectTimeout:
        print("UNKNOWN - Connection timeout!")
        sys.exit(3)
    except requests.exceptions.ConnectionError:
        print("UNKNOWN - Connection failed: " + str(sys.exc_info()[1]))
        sys.exit(3)
    except:
        print("UNKNOWN - Unexpected error: " + str(sys.exc_info()))
        sys.exit(3)


def check_sensors(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/sensor-status"
    data = get_data(url, key)
    for item in data["sensors"]:
        if verbose:
            output += "\nName: " + str(item["sensor-name"]) + ", value: " + str(item["value"]) + ", status: " + str(
                item["status"])
        if item["status"] != "OK":
            if not verbose:
                output += "\nName: " + str(item["sensor-name"]) + ", value: " + str(item["value"]) + ", status: " + str(
                    item["status"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_ports(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/ports"
    data = get_data(url, key)
    for item in data["port"]:
        if verbose:
            output += "\nPort: " + str(item["port"]) + ", status: " + str(item["status"]) + ", health: " + str(
                item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nPort: " + str(item["port"]) + ", status: " + str(item["status"]) + ", health: " + str(
                    item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_disks(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/disks"
    data = get_data(url, key)
    for item in data["drives"]:
        if verbose:
            output += "\nDisk in slot: " + str(item["slot"]) + ", vendor: " + str(item["vendor"]) + ", SN: " + str(
                item["serial-number"]) + ", health: " + str(item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nDisk in slot: " + str(item["slot"]) + ", vendor: " + str(item["vendor"]) + ", SN: " + str(
                    item["serial-number"]) + ", health: " + str(item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_psu(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/power-supplies"
    data = get_data(url, key)
    for item in data["power-supplies"]:
        if verbose:
            output += "\nName: " + str(item["name"]) + ", SN: " + str(item["serial-number"]) + ", health: " + str(
                item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nName: " + str(item["name"]) + ", SN: " + str(item["serial-number"]) + ", health: " + str(
                    item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_controllers(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/controllers"
    data = get_data(url, key)
    for item in data["controllers"]:
        if verbose:
            output += "\nController ID: " + str(item["controller-id"]) + ", status: " + str(
                item["status"]) + ", SN: " + str(item["serial-number"]) + ", health: " + str(item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nController ID: " + str(item["controller-id"]) + ", status: " + str(
                    item["status"]) + ", SN: " + str(item["serial-number"]) + ", health: " + str(item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_fans(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/fans"
    data = get_data(url, key)
    for item in data["fan"]:
        if verbose:
            output += "\nName: " + str(item["name"]) + ", status: " + str(item["status"]) + ", location: " + str(
                item["location"]) + ", health: " + str(item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nName: " + str(item["name"]) + ", status: " + str(item["status"]) + ", location: " + str(
                    item["location"]) + ", health: " + str(item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


def check_volumes(hostname, key):
    global output, exit_code, verbose
    url = "https://" + str(hostname) + "/api/show/volumes"
    data = get_data(url, key)
    for item in data["volumes"]:
        if verbose:
            output += "\nVolumes name: " + str(item["volume-name"]) + ", volume group: " + str(
                item["volume-group"]) + ", health: " + str(item["health"])
        if item["health"] != "OK":
            if not verbose:
                output += "\nVolumes name: " + str(item["volume-name"]) + ", volume group: " + str(
                    item["volume-group"]) + ", health: " + str(item["health"])
            output += " (!!)"
            exit_code = 2
    if verbose:
        output += "\n-----------------------------"


if __name__ == "__main__":
    hostname = ""
    username = ""
    password = ""
    verbose = False
    checks = []
    output = ""
    exit_code = 0

    try:
        parser = argparse.ArgumentParser(
            description="Nagios plugin to monitor health of Your PowerVault.",
            epilog="""
            Short description of checks option:
            all - show all checks
            sensors - show status of system sensors
            disk - show status of drives
            ports - show numbers of ports linkup, used, and link down (raise alert if port is used and port is link down)
            fan - show status of fans
            controllers - check controller status
            volume - show volumes, checks if volume is operating normally
            psu - show status of powersupply and fans
                   """,
            formatter_class=RawTextHelpFormatter,
            usage=SUPPRESS)
        parser.add_argument("-H", metavar="host address", help="(Required) IP or hostname", required=True)
        parser.add_argument("-u", metavar="api username", help="(Required) Your API username", required=True)
        parser.add_argument("-p", metavar="api password", help="(Required) Your API username", required=True)
        parser.add_argument('-v', help="(Optional) List full output (not only alerts), default: off",
                            default=False, action="store_true")
        parser.add_argument("-c", metavar="all sensors disk ports fan controllers volume psu",
                            help="(Required) List of checks, choose all, one or few.",
                            nargs="+", choices=["all", "sensors", "disk", "ports", "fan", "controllers", "volume", "psu"], required=True)
        args = parser.parse_args()
    except SystemExit as error:
        if error.code == 2:
            parser.print_help()
        sys.exit(3)
    except:
        parser.print_help()
        sys.exit(3)

    # Assign parsed arguments to variables
    hostname = args.H
    username = args.u
    password = args.p
    verbose = args.v
    checks = args.c

    session_key = get_sessionkey(hostname, username, password)

    if "all" in checks:
        check_sensors(hostname, session_key)
        check_disks(hostname, session_key)
        check_ports(hostname, session_key)
        check_fans(hostname, session_key)
        check_controllers(hostname, session_key)
        check_volumes(hostname, session_key)
        check_psu(hostname, session_key)
    else:
        if "sensors" in checks:
            check_sensors(hostname, session_key)
        if "disk" in checks:
            check_disks(hostname, session_key)
        if "ports" in checks:
            check_disks(hostname, session_key)
        if "fan" in checks:
            check_fans(hostname, session_key)
        if "controllers" in checks:
            check_psu(hostname, session_key)
        if "volume" in checks:
            check_psu(hostname, session_key)
        if "psu" in checks:
            check_psu(hostname, session_key)

    if exit_code == 0:
        if verbose:
            print("OK: No problem detected.\n" + output)
        else:
            print("OK: No problem detected." + output)
    else:
        if exit_code == 1:
            print("WARNING: Some problem detected!\n" + output)
        if exit_code == 2:
            print("CRITICAL: Some problem detected!\n" + output)

    sys.exit(exit_code)
