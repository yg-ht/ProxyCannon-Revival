#!/usr/bin/env python
# Original Author: Hans Lakhan
# Current maintainer: Felix Ryan of You Gotta Hack That

#######################

import argparse
import datetime
import hashlib
import os
import re
import signal
import subprocess
import sys
import time
from subprocess import run
import boto.ec2
import netifaces as netifaces
import random


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def error(msg):
    print("[" + bcolors.FAIL + "!" + bcolors.ENDC + "] " + str(msg))


def success(msg):
    print("[" + bcolors.OKGREEN + "*" + bcolors.ENDC + "] " + str(msg))


def warning(msg):
    print("[" + bcolors.WARNING + "~" + bcolors.ENDC + "] " + str(msg))


def debug(msg):
    if args.v:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("[i] " + str(timestamp) + " : " + str(msg))


#############################################################################################
# Run system commands (outside of Python)
#############################################################################################
def run_sys_cmd(description, islocal, cmd, reportErrors=True):
    if islocal:
        target = 'local'
    else:
        target = 'remote'
    debug(description)
    debug("SHELL CMD (%s): %s" % (target, cmd))
    retcode = run(cmd, shell=True, capture_output=True, text=True)
    if retcode.returncode != 0 and reportErrors:
        error("Failure: %s" % description)
        debug("Failed command output is: %s %s" % (str(retcode.stdout), str(retcode.stderr)))
        warning("Continue? (y/n)")
        confirm = input()
        if confirm.lower() != "y":
            warning("Run clean up? (y/n)")
            confirm = input()
            if confirm.lower() != "y":
                exit("Not cleaning, shutting down")
            else:
                cleanup()
                exit("Cleaning complete, shutting down")
    else:
        success("Success: %s" % description)
        return retcode.stdout


#############################################################################################
# Handle Logging
#############################################################################################
def log(msg):
    timestamp = datetime.datetime.now()
    logfile = open("/tmp/" + logName, 'a')
    logfile.write(str(timestamp))
    logfile.write(" : " + str(msg))
    logfile.write("\n")
    logfile.close()


#############################################################################################
# Handle SigTerm & Clean up
#############################################################################################
def cleanup(proxy=None, cannon=None):
    # Time to clean up
    print("\n")

    # Connect to EC2 and return list of reservations
    cleanup_conn = None
    try:
        success("Connecting to Amazon's EC2...")
        cleanup_conn = connect_to_ec2()
    except Exception as e:
        error("Failed to connect to Amazon EC2 because: %s" % e)
        exit(2)

    cleanup_instances = cleanup_conn.get_only_instances(
        filters={"tag:Name": nameTag, "instance-state-name": "running"})

    # Grab list of public IP's assigned to instances that were launched
    all_instances = []
    for instance in cleanup_instances:
        if instance.ip_address not in all_instances:
            if instance.ip_address:
                all_instances.append(instance.ip_address)
    debug("Public IP's for all instances: " + str(all_instances))

    # Cleaning up per-host aspects
    success("Cleaning local config per remote host.....")
    for host in all_instances:
        # Killing ssh tunnel
        run_sys_cmd("Killing ssh tunnel", True, "kill $(ps -ef | grep ssh | grep %s | awk {'print $2'})" % host, False)

        # Delete local routes
        run_sys_cmd("Delete route %s dev %s" % (host, networkInterface), True, localcmdsudoprefix +
                    "route del %s dev %s" % (host, networkInterface))

        # Destroying local tun interfaces
        run_sys_cmd("Destroying local tun interfaces", True, localcmdsudoprefix +
                    "ip tuntap del dev tun%s mode tun" % int(ip_to_tunnelid_map[str(host)]))

    # Flush iptables
    run_sys_cmd("Flushing iptables NAT chain", True, "%s iptables -t nat -F" % localcmdsudoprefix)
    run_sys_cmd("Flushing remaining iptables state", True, "%s iptables -F" % localcmdsudoprefix)
    run_sys_cmd("Restoring old iptables state", True, "%s iptables-restore  < /tmp/%s" %
                (localcmdsudoprefix, iptablesName))

    # Replace the custom default route with a standard one that makes sense
    run_sys_cmd("Adding default route", True, localcmdsudoprefix + "ip route replace default via %s dev %s" %
                (defaultgateway, networkInterface))


    # Terminate instance
    success("Terminating Instances.....")
    for instance in cleanup_instances:
        debug("Attempting to terminate instance: %s" % str(instance))
        instance.terminate()

    warning("Pausing for 90 seconds so instances can properly terminate.....")
    time.sleep(90)

    # Remove Security Groups
    success("Deleting Amazon Security Groups.....")
    try:
        cleanup_conn.delete_security_group(name=securityGroup)
    except Exception as e:
        error("Deletion of security group failed because %s" % e)

    # Remove Key Pairs
    success("Removing SSH keys.....")
    try:
        cleanup_conn.delete_key_pair(key_name=keyName)
    except Exception as e:
        error("Deletion of key pair failed because %s" % e)

    # Remove local ssh key
    run_sys_cmd("Remove local ssh key", True, "rm -f %s/.ssh/%s.pem" % (homeDir, keyName))

    # Remove local routing
    run_sys_cmd("Disable local IP forwarding", True, localcmdsudoprefix + "echo 0 | "
                + localcmdsudoprefix + "tee -a /proc/sys/net/ipv4/ip_forward")

    # remove iptables saved config
    run_sys_cmd("Removing local iptables save state", True, localcmdsudoprefix + "rm -rf  /tmp/%s" + iptablesName)

    # Log then close
    log("ProxyCannon-Temp Finished.")

    success("Done!")

    sys.exit(0)


#############################################################################################
# Connect to AWS EC2
#############################################################################################

def connect_to_ec2():
    EC2conn = None
    try:
        debug("Connecting to Amazon's EC2.")
        EC2conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id,
                                             aws_secret_access_key=aws_secret_access_key)
    except Exception as e:
        warning("Failed to connect to Amazon EC2 because: %s" % e)
        warning("Continue? (y/n)")
        confirm = input()
        if confirm.lower() != "y":
            warning("Run clean up? (y/n)")
            confirm = input()
            if confirm.lower() != "y":
                exit("Not cleaning, shutting down")
            else:
                cleanup()
                exit("Cleaning complete, shutting down")
    return EC2conn


#############################################################################################
# Rotate Hosts
#############################################################################################
def rotate_host(instance):
    host = instance.ip_address
    debug("Rotating IP for: " + str(host))

    #########################################################################################
    # Identify the instances so we can create routing tables for tear down
    #########################################################################################

    # get list of instances
    ipfilter_instances = None
    try:
        ipfilter_instances = rotate_conn.get_only_instances(
            filters={"tag:Name": nameTag, "instance-state-name": "running"})
    except Exception as e:
        error("Failed to get instances because: %s (ipfilter_reservations)." % e)

    # get public IP's assigned to instances
    ipfilter = []
    for ipfilter_instance in ipfilter_instances:
        ipfilter.append(ipfilter_instance.ip_address)
    debug("Public IP's for all instances: " + str(ipfilter))

    #########################################################################################
    # Tear down
    #########################################################################################

    # implement multipath routing that doesn't include the host we are tearing down
    nexthopcmd = "ip route replace default scope global "
    route_interface = 0
    while route_interface < args.num_of_instances:
        if int(route_interface) != int(ip_to_tunnelid_map[str(host)]):
            nexthopcmd = nexthopcmd + "nexthop via 10." + str(route_interface) + ".254.1 dev tun" + \
                         str(route_interface) + " weight 1 "
            # As we are using multipath routing and will do route cache-busting elsewhere
            # it is (probably?) good enough to do ECMP here (i.e. weight = 1 for all routes)
        route_interface = route_interface + 1
    # Install new (reduced) routes
    run_sys_cmd("Installing new route", True, localcmdsudoprefix + nexthopcmd)

    # Pause for a second to allow any existing connections using the old route to close
    time.sleep(1)

    # check to validate that no sessions are established
    # Check TCP RX&TX QUEUE
    while True:
        # netstat -ant | grep ESTABLISHED | grep x.x.x.x | awk '{print $2$3}'
        p1 = subprocess.Popen(['netstat', '-ant'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep', 'ESTABLISHED'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.Popen(['grep', host], stdin=p2.stdout, stdout=subprocess.PIPE)
        awkcmd = ['awk', '{print $2$3}']  # had some problems escaping the single quotes, went with this
        p4 = subprocess.Popen(awkcmd, stdin=p3.stdout, stdout=subprocess.PIPE)
        stat, err = p4.communicate()
        p1.stdout.close()
        p2.stdout.close()
        p3.stdout.close()
        p4.stdout.close()
        debug("Connection Stats " + str(stat.strip()))
        if int(stat) > 0:
            debug("Connection is in use, sleeping and trying again in .5 seconds")
            time.sleep(.5)
        else:
            debug("Connection is free")
            break

    # Killing ssh tunnel
    run_sys_cmd("Killing ssh tunnel", True, "kill $(ps -ef | grep ssh | grep %s | awk '{print $2}')" % host, False)

    # Remove iptables rule allowing SSH to EC2 Host
    run_sys_cmd("Remove iptables rule allowing SSH to EC2 Host", True, localcmdsudoprefix +
                "iptables -t nat -D POSTROUTING -d %s -j RETURN" % host)

    # Remove NAT outbound traffic going through our tunnels
    run_sys_cmd("Remove NAT outbound traffic going through our tunnels", True, localcmdsudoprefix +
                "iptables -t nat -D POSTROUTING -o tun%s -j MASQUERADE" % ip_to_tunnelid_map[str(host)])

    # Remove Static Route to EC2 Host
    run_sys_cmd("Remove Static Route to EC2 Host", True, localcmdsudoprefix + "ip route del %s" % host)

    #########################################################################################
    # Reconfigure EC2
    #########################################################################################

    # To get a new public IP you need to replace the existing one with a temporary (Elastic) IP
    # and then release the temporary IP to be given a permanent public IP.  Bit hacky, but works.

    # Requesting new IP allocation
    temporary_address = None
    try:
        temporary_address = rotate_conn.allocate_address()
    except Exception as e:
        error("Failed to obtain a new address because: " + str(e))
        cleanup()
    debug("Temporary Elastic IP address: " + temporary_address.public_ip)

    # Associating new temporary address
    rotate_conn.associate_address(instance.id, temporary_address.public_ip)

    # At this point, your VM should respond on its public ip address.
    # NOTE: It may take up to 60 seconds for the temporary Elastic IP address to begin working
    debug("Sleeping for 30s to allow for new temporary IP to take effect")
    #time.sleep(30)

    # Remove temporary IP association forcing a new permanent public IP
    try:
        rotate_conn.disassociate_address(temporary_address.public_ip)
    except Exception as e:
        error("Failed to disassociate the address " + str(temporary_address.public_ip) + " because: " + str(e))
        cleanup()
    debug("Sleeping for 60s to allow for new permanent IP to take effect")
    #time.sleep(60)

    # Return the temporary IP address back to address pool
    try:
        rotate_conn.release_address(allocation_id=temporary_address.allocation_id)
    except Exception as e:
        error("Failed to release the address " + str(temporary_address.public_ip) + " because: " + str(e))
        cleanup()

    #########################################################################################
    # Identify the instances so we can create routing tables for stand up
    #########################################################################################

    # Connect to EC2 and get list of instances
    ip_list_conn = connect_to_ec2()
    ip_list_instances = ip_list_conn.get_only_instances(
        filters={"tag:Name": nameTag, "instance-state-name": "running"})

    # Grab list of public IP's assigned to instances that were launched
    all_addresses = []
    for ip_list_instance in ip_list_instances:
        all_addresses.append(ip_list_instance.ip_address)
    debug("Public IP's for all instances: " + str(all_addresses))

    swapped_ip = ''
    # print("all_addresses: " + str(all_addresses))
    for address in all_addresses:
        if address not in ipfilter:
            debug("found new ip: " + str(address))
            swapped_ip = str(address)

    #########################################################################################
    # Stand up
    #########################################################################################

    sshbasecmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s " % (homeDir, keyName, swapped_ip)

    # Add static routes for our SSH tunnels
    run_sys_cmd("Add static routes for our SSH tunnels", True, localcmdsudoprefix +
                "ip route add %s via %s dev %s" % (swapped_ip, defaultgateway, networkInterface))

    # Establish tunnel interface
    sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no -w %s:%s -o TCPKeepAlive=yes -o " \
             "ServerAliveInterval=50 ubuntu@%s &" % (
        homeDir, keyName, ip_to_tunnelid_map[str(host)], ip_to_tunnelid_map[str(host)], swapped_ip)
    debug('SHELL CMD (remote): %s' % sshcmd)
    retry_cnt = 0
    while retry_cnt < 6:
        retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
        if retcode != 0:
            warning("Failed to establish tunnel with %s (tun%s). Retrying..." % (
                swapped_ip, ip_to_tunnelid_map[str(host)]))
            retry_cnt = retry_cnt + 1
            time.sleep(1 + int(retry_cnt))
        else:
            break
        if retry_cnt == 5:
            error("Giving up...")
            cleanup()

    # Provision remote tun interface
    run_sys_cmd("Setting IP on remote tun adapter", False, sshbasecmd +
                "'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" %
                (ip_to_tunnelid_map[str(host)], ip_to_tunnelid_map[str(host)]))

    # Add return route back to us
    run_sys_cmd("Adding return route back to us", False, sshbasecmd +
                "'sudo route add 10.%s.254.2 dev tun%s'" %
                (ip_to_tunnelid_map[str(host)], ip_to_tunnelid_map[str(host)]))

    # Turn up our interface
    run_sys_cmd("Turn up our interface", True, localcmdsudoprefix +
                "ifconfig tun%s up" % ip_to_tunnelid_map[str(host)])

    # Provision interface
    run_sys_cmd("Provision interface", True, localcmdsudoprefix +
                "ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (ip_to_tunnelid_map[str(host)],
                                                                        ip_to_tunnelid_map[str(host)]))
    time.sleep(2)

    # Allow local connections to the proxy server
    run_sys_cmd("Allow connections to our proxy servers", True, localcmdsudoprefix +
                "iptables -t nat -I POSTROUTING -d %s -j RETURN" % swapped_ip)

    # NAT outbound traffic going through our tunnels
    run_sys_cmd("NAT outbound traffic going through our tunnels", True, localcmdsudoprefix +
                "iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " %
                ip_to_tunnelid_map[str(host)])

    # Rebuild Route table
    route_interface = 0
    nexthopcmd = "ip route replace default scope global "
    while route_interface < args.num_of_instances:
        nexthopcmd = nexthopcmd + "nexthop via 10." + str(route_interface) + \
                     ".254.1 dev tun" + str(route_interface) + " weight 1 "
        # see earlier note about accepting ECMP routing (i.e. weight = 1 for all)
        route_interface = route_interface + 1

    run_sys_cmd("Insert custom route command", True, localcmdsudoprefix + nexthopcmd)

    # print address_to_tunnel
    log(str(swapped_ip))

    # reassigning the tunnel ID to the new IP address
    ip_to_tunnelid_map[str(swapped_ip)] = ip_to_tunnelid_map[str(host)]
    del ip_to_tunnelid_map[str(host)]


#############################################################################################
# Perform cache-busting on ECMP routing
#############################################################################################
def cache_bust():
    # Rebuild Route table
    route_interface = 0
    nexthopcmd = "ip route replace default scope global "
    weights = range(1, args.num_of_instances + 1)
    debug("The range of weights to give to routes are: %s" % str(weights))
    random_weights = random.sample(weights, args.num_of_instances)
    debug("The route weights have been ordered as: %s" % str(random_weights))
    while route_interface < args.num_of_instances:
        # generate a random int between 1 and the num of interfaces +1 to be the weight of the route as this is using
        # random.sample the values should not be repeated and we will never have ECMP routing
        nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight %s " % \
                     (route_interface, route_interface, random_weights[int(route_interface)])
        # we do random route weight here to force variation in the use of the multipath routes
        route_interface = route_interface + 1
    run_sys_cmd("Insert custom route command", True, localcmdsudoprefix + nexthopcmd)
    run_sys_cmd("Flushing route cache", True, localcmdsudoprefix + 'ip route flush cache')


#############################################################################################
# Get Interface IP
#############################################################################################
def get_ip_address(ifname):
    ip = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
    debug(ip)
    return ip


#############################################################################################
# Get Default Route
#############################################################################################
def get_default_gateway_linux():
    gws = netifaces.gateways()
    gwip = gws['default'][netifaces.AF_INET][0]
    debug(gwip)
    return gwip


#############################################################################################
# The main event
#############################################################################################
# Generate sshkeyname
def main():
    # Display Warning
    print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("+ This script will clear out any existing iptable and routing rules. +")
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    warning("Would you like to continue y/[N]: ")
    confirm = input()
    if confirm.lower() != "y":
        exit("Yeah you're right its probably better to play it safe.")

    # Initialize connection to EC2
    debug("Connecting to Amazon's EC2...")
    conn = connect_to_ec2()

    # Generate KeyPair
    debug("Generating ssh keypairs...")
    if not os.path.exists("%s/.ssh" % homeDir):
        os.makedirs("%s/.ssh" % homeDir)
        debug("Created %s/.ssh directory" % homeDir)
    keypair = conn.create_key_pair(keyName)
    keypair.material = keypair.material.encode()
    keypair.save("%s/.ssh" % homeDir)
    debug("SSH Key Pair Name " + keyName)
    time.sleep(5)
    success("Generating Amazon Security Group...")
    sg = None
    try:
        sg = conn.create_security_group(name=securityGroup, description="Used for proxyCannon")
    except Exception as e:
        error("Generating Amazon Security Group failed because: %s" % e)
        exit()

    time.sleep(5)
    try:
        sg.authorize(ip_protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0")
    except Exception as e:
        error("Generating Amazon Security Group failed because: %s" % e)
        exit()

    debug("Security Group Name: " + securityGroup)

    # Launch Amazon Instances
    reservations = None
    try:
        reservations = conn.run_instances(args.image_id, key_name=keyName, min_count=args.num_of_instances,
                                          max_count=args.num_of_instances, instance_type=args.image_type,
                                          security_groups=[securityGroup])
    except Exception as e:
        error("Failed to start new instance: %s" % e)
        error("There may be config in your AWS console to tidy up but no local changes were made")
        exit()

    warning("Starting %s instances, waiting about 4 minutes for them to fully boot" % args.num_of_instances)

    # sleep for 4 minutes while booting images
    for i in range(21):
        sys.stdout.write('\r')
        sys.stdout.write("[%-20s] %d%%" % ('=' * i, 5 * i))
        sys.stdout.flush()
        time.sleep(11.5)
    print("\n")
    # Add tag name to instance for better management
    for instance in reservations.instances:
        instance.add_tag("Name", nameTag)
    debug("Tag Name: " + nameTag)

    # Grab list of public IP's assigned to instances that were launched
    allInstances = []
    instances = conn.get_only_instances(filters={"tag:Name": nameTag, "instance-state-name": "running"})
    for instance in instances:
        if instance.ip_address not in allInstances:
            if instance.ip_address:
                allInstances.append(instance.ip_address)
    debug("Public IP's for all instances: " + str(allInstances))

    interface = 0
    # Create ssh Tunnels for socks proxying
    success("Provisioning Hosts.....")
    for host in allInstances:
        log(host)
        sshbasecmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s " % (homeDir, keyName, host)

        # Check connectivity and add the host to known_hosts file
        run_sys_cmd("Checking connectivity via SSH with %s" % host, False, sshbasecmd + "'id'")

        # Enable Tunneling on the remote host
        run_sys_cmd("Enabling tunneling via SSH on %s" % host, False, sshbasecmd +
                    "'echo \"PermitTunnel yes\" | sudo tee -a  /etc/ssh/sshd_config'")

        # Copy Keys
        run_sys_cmd("Copying ssh keys to from normal user to root user on %s" % host, False, sshbasecmd +
                    "'sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/'")

        # Restarting Service to take new config (you'd think a simple reload would be enough)
        run_sys_cmd("Restarting Service to take new config on %s" % host, False, sshbasecmd + "'sudo service ssh "
                                                                                              "restart'")

        # Provision interface
        run_sys_cmd("Provisioning tun%s interface on %s" % (interface, host), False, sshbasecmd +
                    "'sudo ip tuntap add dev tun%s mode tun'" % interface)

        # Configure interface
        run_sys_cmd("Configuring tun%s interface on %s" % (interface, host), False, sshbasecmd +
                    "'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" % (interface, interface))

        # Enable forwarding on remote host
        run_sys_cmd("Enable forwarding on remote host", False, sshbasecmd + "'sudo su root -c \"echo 1 > "
                                                                            "/proc/sys/net/ipv4/ip_forward\"'")

        # Provision iptables on remote host
        run_sys_cmd("Provision iptables on remote host", False, sshbasecmd + "'sudo iptables -t nat -A POSTROUTING "
                                                                             "-o eth0 -j MASQUERADE'")

        # Add return route back to us
        run_sys_cmd("Add return route back to us", False, sshbasecmd + "'sudo route add 10.%s.254.2 dev tun%s'"
                    % (interface, interface))

        # Create tun interface
        run_sys_cmd("Creating local interface tun%s" % str(interface), True, localcmdsudoprefix +
                    "ip tuntap add dev tun%s mode tun" % str(interface))

        # Turn up our interface
        run_sys_cmd("Turning up interface tun%s" % str(interface), True, localcmdsudoprefix +
                    "ifconfig tun%s up" % interface)

        # Provision interface
        run_sys_cmd("Assigning interface tun" + str(interface) + " ip of 10." + str(interface) + ".254.2", True,
                    localcmdsudoprefix + "ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (interface, interface))
        time.sleep(2)

        # Establish tunnel interface
        sshcmd = "ssh -i %s/.ssh/%s.pem -w %s:%s -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o " \
                 "ServerAliveInterval=50 ubuntu@%s &" % \
                 (homeDir, keyName, interface, interface, host)
        debug("SHELL CMD (remote): " + sshcmd)
        retry_cnt = 0
        while retry_cnt < 6:
            retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
            if retcode != 0:
                warning("Failed to establish ssh tunnel on %s. Retrying..." % host)
                retry_cnt = retry_cnt + 1
                time.sleep(1)
            else:
                break
            if retry_cnt == 5:
                error("Giving up...")
                cleanup()

        # increment for the next lop iteration
        interface = interface + 1

        # add entry to table
        ip_to_tunnelid_map[str(host)] = str(interface - 1)

    # setup local forwarding
    run_sys_cmd("Enabling local ip forwarding", True, "echo 1 | " + localcmdsudoprefix +
                "tee -a /proc/sys/net/ipv4/ip_forward")

    # Save iptables
    run_sys_cmd("Saving the current local IP tables state", True, localcmdsudoprefix +
                "/sbin/iptables-save > /tmp/%s" % iptablesName)

    # Flush existing rules (1 of 3)
    run_sys_cmd("Flushing existing local iptables nat rules", True, localcmdsudoprefix + "iptables -t nat -F")

    # Flush existing rules (2 of 3)
    run_sys_cmd("Flushing existing local iptables mangle rules", True, localcmdsudoprefix + "iptables -t mangle -F")

    # Flush existing rules (3 of 3)
    run_sys_cmd("Flushing all remaining local iptables rules", True, localcmdsudoprefix + "iptables -F")

    # Allow local connections to RFC1918 (1 of 3)
    run_sys_cmd("Allowing local connections to RFC1918 (1 of 3)", True, localcmdsudoprefix +
                "iptables -t nat -I POSTROUTING -d 192.168.0.0/16 -j RETURN")

    # Allow local connections to RFC1918 (2 of 3)
    run_sys_cmd("Allowing local connections to RFC1918 (2 of 3)", True, localcmdsudoprefix +
                "iptables -t nat -I POSTROUTING -d 172.16.0.0/16 -j RETURN")

    # Allow local connections to RFC1918 (3 of 3)
    run_sys_cmd("Allowing local connections to RFC1918 (3 of 3)", True, localcmdsudoprefix +
                "iptables -t nat -I POSTROUTING -d 10.0.0.0/8 -j RETURN")

    count = args.num_of_instances
    interface = 1
    nexthopcmd = "ip route replace default scope global "
    for host in allInstances:
        # Allow connections to our proxy servers
        run_sys_cmd("Allowing connections to our proxy servers", True, localcmdsudoprefix +
                    "iptables -t nat -I POSTROUTING -d %s -j RETURN" % host)

        # NAT outbound traffic going through our tunnels
        run_sys_cmd("NAT outbound traffic so that it goes through our tunnels", True, localcmdsudoprefix +
                    "iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " % (interface - 1))

        # Build round robin route table command
        nexthopcmd = nexthopcmd + "nexthop via 10." + str(interface - 1) + ".254.1 dev tun" + str(
            interface - 1) + " weight 1 "

        # Add static routes for our SSH tunnels
        run_sys_cmd("Adding static routes for our SSH tunnels", True, localcmdsudoprefix +
                    "ip route add %s via %s dev %s" % (host, defaultgateway, networkInterface))

        interface = interface + 1
        count = count - 1

    # Replace default route with the new default route
    run_sys_cmd("Replace default route with the new default route", True, localcmdsudoprefix + "%s" % nexthopcmd)

    success("Done!")
    print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("+ Leave this terminal open and start another to run your commands.   +")
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    print("[" + bcolors.WARNING + "~" + bcolors.ENDC + "] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC +
          " to terminate the script gracefully.")


#############################################################################################
# System and Program Arguments
#############################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-id', '--image-id', nargs='?', default='ami-d05e75b8',
                    help="Amazon ami image ID.  Example: ami-d05e75b8. If not set, ami-d05e75b8.")
parser.add_argument('-t', '--image-type', nargs='?', default='t2.nano',
                    help="Amazon ami image type Example: t2.nano. If not set, defaults to t2.nano.")
parser.add_argument('--region', nargs='?', default='us-east-1',
                    help="Select the region: Example: us-east-1. If not set, defaults to us-east-1.")
parser.add_argument('-r', action='store_true', help="Enable Rotating AMI hosts.")
parser.add_argument('-b', action='store_true', help="Enable multipath cache busting.")
parser.add_argument('-v', action='store_true', help="Enable verbose logging. All cmd's should be printed to stdout")
parser.add_argument('num_of_instances', type=int, help="The number of amazon instances you'd like to launch.")
parser.add_argument('--name', nargs="?", help="Set the name of the instance in the cluster")
parser.add_argument('-i', '--interface', nargs='?', default='detect',
                    help="Interface to use, default will result in detecting the default gateway and using that")
parser.add_argument('-l', '--log', action='store_true',
                    help="Enable logging of WAN IP's traffic is routed through. Output is to /tmp/")
args = parser.parse_args()

# system variables;
homeDir = os.getenv("HOME")
FNULL = open(os.devnull, 'w')
debug("Homedir: " + homeDir)
ip_to_tunnelid_map = {}

#############################################################################################
# Sanity Checks and set up
#############################################################################################
# Check if running as root
debug("Checking for root / sudo privileges")
if os.geteuid() != 0:
    warning("You are not running as root so will be asked for sudo password when needed.")
    localcmdsudoprefix = 'sudo '
else:
    localcmdsudoprefix = ''

# Check for required programs
debug("Checking for required programs")
if not os.path.isfile("/sbin/iptables-save"):
    error("Could not find /sbin/iptables-save")
    exit()
if not os.path.isfile("/sbin/iptables-restore"):
    error("Could not find /sbin/iptables-restore")
    exit()
if not os.path.isfile("/sbin/iptables"):
    error("Could not find /sbin/iptables")
    exit()

# Check args
debug("Checking for minimum num of args")
if args.num_of_instances < 1:
    error("You need at least 1 instance")
    exit()
elif args.num_of_instances > 20:
    warning("Woah there stallion, that's a lot of instances, hope you got that sweet license from Amazon.")

# Check for boto config
boto_config = homeDir + "/.boto"
aws_secret_access_key = None
aws_access_key_id = None
if os.path.isfile(boto_config):
    for line in open(boto_config):
        pattern = re.findall("^aws_access_key_id = (.*)\n", line, re.DOTALL)
        if pattern:
            aws_access_key_id = pattern[0]
        pattern = re.findall("^aws_secret_access_key = (.*)\n", line, re.DOTALL)
        if pattern:
            aws_secret_access_key = pattern[0]
else:
    debug("boto config file does not exist")
    aws_access_key_id = input("What is the AWS Access Key Id: ")
    aws_secret_access_key = input("What is the AWS Secret Access Key: ")

    boto_fh = open(boto_config, 'w+')
    boto_fh.write('[default]')
    boto_fh.write("\n")
    boto_fh.write('aws_access_key_id = ')
    boto_fh.write(aws_access_key_id)
    boto_fh.write("\n")
    boto_fh.write('aws_secret_access_key = ')
    boto_fh.write(aws_secret_access_key)
    boto_fh.write("\n")
    boto_fh.close()

debug("AWS_ACCESS_KEY_ID: " + aws_access_key_id)
debug("AWS_SECRET_ACCESS_KEY: " + aws_secret_access_key)

if args.name:
    # SSH Key Name
    keyName = "PC_" + args.name
    # AMI Security Group Name
    securityGroup = "PC_" + args.name
    # AMI Tag Name
    nameTag = "PC_" + args.name
    # iptables Name
    iptablesName = "PC_" + args.name
    # log name
    logName = "PC_" + args.name + ".log"
else:
    pid = os.getpid()
    stamp = time.time()
    m = hashlib.md5()
    tempstring = str(pid + stamp).encode('utf-8')
    m.update(tempstring)

    # SSH key Name
    keyName = "PC_" + m.hexdigest()
    # AMI Security Group Name
    securityGroup = "PC_" + m.hexdigest()
    # AMI Tag Name
    nameTag = "PC_" + m.hexdigest()
    # iptables Name
    iptablesName = "PC_" + m.hexdigest()
    # Log Name
    logName = "PC_" + m.hexdigest() + ".log"

if args.interface != 'detect':
    networkInterface = args.interface
else:
    gws = netifaces.gateways()
    networkInterface = gws['default'][netifaces.AF_INET][1]
debug(networkInterface)

if networkInterface in netifaces.interfaces():
    localIP = get_ip_address(networkInterface)
    debug("Local Interface IP for " + networkInterface + ": " + localIP)
    defaultgateway = get_default_gateway_linux()
    debug("IP address of default gateway: " + defaultgateway)
    debug("Opening logfile: /tmp/" + logName)
    log("Proxy Cannon Started.")
else:
    defaultgateway = None
    error("Network interface not found")
    exit()

# Define SigTerm Handler
signal.signal(signal.SIGINT, cleanup)

if __name__ == '__main__':
    main()
    while True:
        if args.r:
            success("Rotating infrastructure IPs.")
            # connect to EC2
            rotate_conn = connect_to_ec2()

            # return list of reservations
            rotate_reservations = rotate_conn.get_only_instances(filters={"tag:Name": nameTag,
                                                                          "instance-state-name": "running"})

            # loop round detected instances of each reservation
            for instance in rotate_reservations:
                rotate_host(instance)
        if args.b:
            success("Performing multipath cache bust")
            cache_bust()
        # the below sleep is just to stop wild things from happening until proper timing control is implemented.
        time.sleep(5)
