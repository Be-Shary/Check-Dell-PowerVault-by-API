# Check Dell PowerVault by API


## Installation + Requirements
* python2.7 -> python -m pip install requests==2.7.0 
* python 2.6 ->  sudo yum install python-requests

## Nagios configuration
Sample configuration files:

commands.cfg file:

    define command{
            command_name    check_dell_powervault
            command_line    /usr/bin/python $USER1$/check_powervault_api.py -H $HOSTADDRESS$ $ARG1$
    }

host.cfg file:

    define host {
    use                            generic-host
    host_name                      test-dell-powervault-cluster
    alias                          test-dell-powervault-cluster
    address                        10.200.20.100
    }

    define service {
    use                            generic-service
    host_name                      test-dell-powervault-cluster
    service_description            Dell PowerVault Health Check
    check_command                  check_dell_powervault!-u mon -p 'qwerty123?' -f 80,90 -c all -v
    }


## Usage
check_powervault_api.py -H IP/hostname -u user -p 'password' -c all -v

options:
*   -h, --help            show this help message and exit
*   -H host address       (Required) IP or hostname
*   -u api username       (Required) Your API username
*   -p api password       (Required) Your API username
*   -v                    (Optional) List full output (not only alerts), default: off
*   -c all sensors disk ports fan controllers volume psu [all sensors disk ports fan controllers volume psu ...]
                        (Required) List of checks, choose all, one or few.

            Short description of checks option:
            all - show all checks
            sensors - show status of system sensors
            disk - show status of drives
            ports - show numbers of ports linkup, used, and link down (raise alert if port is used and port is link down)
            fan - show status of fans
            controllers - check controller status
            volume - show volumes, checks if volume is operating normally
            psu - show status of powersupply and fans
