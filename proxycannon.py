#!/usr/bin/env python3
# Original Author: Hans Lakhan
# Current maintainer: Felix Ryan of You Gotta Hack That

#######################
import sys
# check Python version is >= 3.5 before we do anything else
if sys.version_info.major != 3 or sys.version_info.minor < 5:
    print("This script needs Python >= 3.5.  You are running Python %s" % sys.version)
    exit()
import argparse
import datetime
import hashlib
import os
import re
import signal
import subprocess
import time
from subprocess import run
import boto.ec2
import netifaces as netifaces
import random
import threading
from concurrent import futures
from math import floor


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


########################################################################################################################
# Run system commands (outside of Python)
########################################################################################################################
def run_sys_cmd(description, islocal, cmd, report_errors=True, show_log=True):
    if islocal:
        target = 'local'
    else:
        target = 'remote'
    if show_log:
        debug(description)
    if show_log:
        debug("SHELL CMD (%s): %s" % (target, cmd))
    retcode = run(cmd, shell=True, capture_output=True, text=True)
    if retcode.returncode != 0 and report_errors:
        error("Failure: %s" % description)
        debug("Failed command output is: %s %s" % (str(retcode.stdout), str(retcode.stderr)))
        warning("Continue? y/[N]")
        confirm = input()
        if confirm.lower() != "y":
            warning("Run clean up? y/[N]")
            confirm = input()
            if confirm.lower() != "y":
                exit("Not cleaning, shutting down")
            else:
                cleanup()
                exit("Cleaning complete, shutting down")
    else:
        if show_log:
            success("Success: %s" % description)
        return retcode.stdout


########################################################################################################################
# Handle Logging
########################################################################################################################
def log(msg):
    timestamp = datetime.datetime.now()
    logfile = open("/tmp/" + logName, 'a')
    logfile.write(str(timestamp))
    logfile.write(" : " + str(msg))
    logfile.write("\n")
    logfile.close()


########################################################################################################################
# Handle SigTerm & Clean up
########################################################################################################################
def cleanup(proxy=None, cannon=None):
    ####################################################################################################################
    # Cleaning up per-host aspects
    ####################################################################################################################
    success("\nCleaning local config per remote host.....")

    # set the exit flag
    exit_threads = True

    # set all indicators that all tunnels should not be used so that any active threads are updated as early as possible
    for tunnel_id, tunnel in tunnels.items():
        tunnels[tunnel_id]['route_active'] = False
        tunnels[tunnel_id]['tunnel_active'] = False
        tunnels[tunnel_id]['link_state_active'] = False

    for tunnel_id, tunnel in tunnels.items():
        # Killing ssh tunnel
        run_sys_cmd("Killing ssh tunnel", True,
                    "kill $(ps -ef | grep ssh | grep %s | awk {'print $2'})" % tunnel['pub_ip'], False)

        # Delete local routes
        run_sys_cmd("Delete route %s dev %s" % (tunnel['pub_ip'], networkInterface), True, localcmdsudoprefix +
                    "route del %s dev %s" % (tunnel['pub_ip'], networkInterface), report_errors=False)

        # Destroying local tun interfaces
        run_sys_cmd("Destroying local tun interfaces", True, localcmdsudoprefix +
                    "ip tuntap del dev tun%s mode tun" % tunnel_id)

    ########################################################################################################################
    # Cleaning up local aspects
    ########################################################################################################################

    # Flush iptables
    run_sys_cmd("Flushing iptables NAT chain", True, "%s iptables -t nat -F" % localcmdsudoprefix)
    run_sys_cmd("Flushing remaining iptables state", True, "%s iptables -F" % localcmdsudoprefix)
    run_sys_cmd("Restoring old iptables state", True, "%s iptables-restore  < /tmp/%s" %
                (localcmdsudoprefix, iptablesName))

    # Replace the custom default route with a standard one that makes sense
    run_sys_cmd("Re-adding normal default route", True, localcmdsudoprefix + "ip route replace default via %s dev %s" %
                (defaultgateway, networkInterface))

    # Remove local ssh key
    run_sys_cmd("Remove local ssh key", True, "rm -f %s/.ssh/%s.pem" % (homeDir, keyName))

    # Remove local IP forwarding
    run_sys_cmd("Disable local IP forwarding", True, localcmdsudoprefix + "echo 0 | "
                + localcmdsudoprefix + "tee -a /proc/sys/net/ipv4/ip_forward")

    # remove iptables saved config
    run_sys_cmd("Removing local iptables save state", True, localcmdsudoprefix + "rm -rf  /tmp/%s" + iptablesName)

    ########################################################################################################################
    # Cleaning up cloud aspects
    ########################################################################################################################

    # Connect to EC2 and return list of reservations
    cleanup_conn = None
    try:
        success("Connecting to Amazon's EC2...")
        cleanup_conn = connect_to_ec2()
    except Exception as e:
        error("Failed to connect to Amazon EC2 because: %s" % e)
        exit(2)

    debug("Getting objects ready for termination at the cloud")
    cleanup_instances = cleanup_conn.get_only_instances(
        filters={"tag:Name": nameTag, "instance-state-name": "running"})
    # Terminate instances
    success("Terminating Instances.....")
    for instance in cleanup_instances:
        debug("Attempting to terminate instance: %s" % str(instance.id))
        instance.terminate()

    warning("Pausing for 120 seconds so instances can properly terminate.....")
    time.sleep(120)

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

    # Log then close
    log("ProxyCannon-Temp Finished.")

    success("Done!")

    sys.exit(0)


########################################################################################################################
# Connect to AWS EC2
########################################################################################################################
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


########################################################################################################################
# Rotate Hosts
########################################################################################################################
def rotate_host(targettunnel_id, show_log=True):
    # connect to EC2 (presumably in case it closed since tool launch?)
    rotate_conn = connect_to_ec2()

    if show_log:
        debug("Rotating IP for: tun%s with IP %s" % (targettunnel_id, tunnels[targettunnel_id]['pub_ip']))

    #########################################################################################
    # Identify the instances so we can create routing tables for tear down
    #########################################################################################

    # check if the exit flag has been set
    if exit_threads:
        return

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
    if show_log:
        debug("Public IP's for all instances: " + str(ipfilter))

    #########################################################################################
    # Tear down
    #########################################################################################

    # check if the exit flag has been set
    if exit_threads:
        return

    # mark target route as inactive
    tunnels[targettunnel_id]['route_active'] = False

    # implement multipath routing that doesn't include the host we are tearing down
    routes_available = False
    nexthopcmd = "ip route replace default scope global "
    for tunnel_id, tunnel in tunnels.items():
        # don't include the host we are tearing down in the multipath routing or any others that have been disabled
        if tunnel['route_active'] and tunnel['tunnel_active'] and tunnel['link_state_active']:
            nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight 1 " % (tunnel_id, tunnel_id)
            # As we are using multipath routing and will do route cache-busting elsewhere
            # it is (probably?) good enough to do ECMP here (i.e. weight = 1 for all routes)
            routes_available = True
        else:
            if show_log:
                debug("Tunnel tun%s is not suitable so not including in route table. (Route %s - Tunnel %s - Link %s)" %
                      (tunnel_id, str(tunnel['route_active']), str(tunnel['tunnel_active']),
                       str(tunnel['link_state_active'])))
    # Install new (reduced) routes
    if routes_available:
        run_sys_cmd("Installing new multipath route", True, localcmdsudoprefix + nexthopcmd, show_log=show_log)
    else:
        error("No routes available - not installing new default multipath route - exiting Host IP Rotation")
        return 2

    # Pause for a second to allow any existing connections using the old route to close
    time.sleep(1)

    # wait until no sessions are established
    # Check TCP RX&TX QUEUE
    while True:
        connection_stats = run_sys_cmd('Checking whether the SSH tunnel has any packets queued', True,
                                       "netstat -ant | grep ESTABLISHED | grep %s | awk {'print $2\":\"$3'}" %
                                       tunnels[targettunnel_id]['pub_ip'], show_log=show_log)
        debug("Connection Stats for tun%s are: %s" % (targettunnel_id, str(connection_stats).rstrip()))
        if str(connection_stats).rstrip() == "00" or str(connection_stats).rstrip() == '':
            if show_log:
                debug("Connection is free (tun%s)" % targettunnel_id)
            break
        else:
            if show_log:
                debug("Connection is in use, sleeping and trying again in 0.5 seconds (tun%s)" % targettunnel_id)
            time.sleep(0.5)

    # marking ssh tunnel as inactive
    tunnels[targettunnel_id]['tunnel_active'] = False
    # Killing ssh tunnel
    run_sys_cmd("Killing ssh tunnel", True, "kill $(ps -ef | grep ssh | grep %s | awk '{print $2}')" %
                tunnels[targettunnel_id]['pub_ip'], report_errors=False, show_log=show_log)

    # Remove iptables rule allowing SSH to EC2 Host
    run_sys_cmd("Remove iptables rule allowing SSH to EC2 Host", True, localcmdsudoprefix +
                "iptables -t nat -D POSTROUTING -d %s -j RETURN" % tunnels[targettunnel_id]['pub_ip'], show_log=show_log)

    # Remove NAT outbound traffic going through our tunnels
    run_sys_cmd("Remove NAT outbound traffic going through our tunnels", True, localcmdsudoprefix +
                "iptables -t nat -D POSTROUTING -o tun%s -j MASQUERADE" % targettunnel_id, show_log=show_log)

    # Remove Static Route to EC2 Host
    run_sys_cmd("Remove Static Route to EC2 Host", True, localcmdsudoprefix + "ip route del %s" %
                tunnels[targettunnel_id]['pub_ip'], show_log=show_log)

    #########################################################################################
    # Reconfigure EC2
    #########################################################################################

    # check if the exit flag has been set
    if exit_threads:
        return

    # To get a new public IP you need to replace the existing one with a temporary (Elastic) IP
    # and then release the temporary IP to be given a permanent public IP.  Bit hacky, but works.

    # Requesting new IP allocation
    if show_log:
        debug("Requsting new temporary Elastic IP address... This can take a while (tun%s)" % targettunnel_id)
    temporary_address = None
    try:
        temporary_address = rotate_conn.allocate_address()
    except Exception as e:
        error("Failed to obtain a new address because: " + str(e))
        cleanup()
    if show_log:
        debug("Temporary Elastic IP address: %s (tun%s)" % (temporary_address.public_ip, targettunnel_id))

    # Associating new temporary address
    rotate_conn.associate_address(tunnels[targettunnel_id]['cloud_id'], temporary_address.public_ip)

    # At this point, your VM should respond on its public ip address.
    # NOTE: It may take up to 60 seconds for the temporary Elastic IP address to begin working
    if show_log:
        debug("Sleeping for 30s to allow for new temporary IP to take effect (tun%s)" % targettunnel_id)
    time.sleep(30)

    # Remove temporary IP association forcing a new permanent public IP
    try:
        rotate_conn.disassociate_address(temporary_address.public_ip)
    except Exception as e:
        error("Failed to disassociate the address " + str(temporary_address.public_ip) + " because: " + str(e))
        cleanup()
    if show_log:
        debug("Sleeping for 60s to allow for new permanent IP to take effect (tun%s)" % targettunnel_id)
    time.sleep(60)

    # Return the temporary IP address back to address pool
    try:
        rotate_conn.release_address(allocation_id=temporary_address.allocation_id)
    except Exception as e:
        error("Failed to release the address " + str(temporary_address.public_ip) + " because: " + str(e))
        cleanup()

    if show_log:
        debug("Rotate host completed for tun%s" % targettunnel_id)

    #########################################################################################
    # Identify the instances so we can create routing tables for stand up
    #########################################################################################

    # check if the exit flag has been set
    if exit_threads:
        return

    # Connect to EC2 and get list of instances
    if show_log:
        debug("Refreshing our local list of instances from the cloud provider to identify new permanent IP (tun%s)" % targettunnel_id)
    ip_list_instances = rotate_conn.get_only_instances(
        filters={"tag:Name": nameTag, "instance-state-name": "running"})

    # Grab list of public IP's assigned to instances that were launched
    all_addresses = []
    for ip_list_instance in ip_list_instances:
        all_addresses.append(ip_list_instance.ip_address)
    if show_log:
        debug("Public IP's for all instances: " + str(all_addresses))

    swapped_ip = ''
    # print("all_addresses: " + str(all_addresses))
    for address in all_addresses:
        if address not in ipfilter:
            if show_log:
                debug("found new ip: %s (tun%s)" % (str(address), targettunnel_id))
            swapped_ip = str(address)

    # if by this point swapped_ip is not defined then something has gone wrong and we should not proceed
    if swapped_ip != '':
        # print address_to_tunnel
        log(str(swapped_ip))

        # updating the internal data structure so that this tunnel_id has the new IP address
        tunnels[targettunnel_id]['pub_ip'] = str(swapped_ip)

        #########################################################################################
        # Stand up
        #########################################################################################

        # check if the exit flag has been set
        if exit_threads:
            return

        sshbasecmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s " % (homeDir, keyName, swapped_ip)

        # Add static routes for new IP to tunnel
        run_sys_cmd("Add static routes for the new IP address on the SSH tunnel", True, localcmdsudoprefix +
                    "ip route add %s via %s dev %s" % (swapped_ip, defaultgateway, networkInterface), show_log=show_log)

        # Establish tunnel
        sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no -w %s:%s -o TCPKeepAlive=yes -o " \
                 "ServerAliveInterval=50 ubuntu@%s &" % (homeDir, keyName, targettunnel_id, targettunnel_id, swapped_ip)
        if show_log:
            debug('SHELL CMD (remote): %s (tun%s)' % (sshcmd, targettunnel_id))
        retry_cnt = 0
        while retry_cnt < 6:
            retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
            if retcode != 0:
                warning("Failed to establish tunnel with %s (tun%s). Retrying..." % (
                    swapped_ip, targettunnel_id))
                retry_cnt = retry_cnt + 1
                time.sleep(1 + int(retry_cnt))
            else:
                ssh_tunnel_pid = run_sys_cmd('Getting PID of newly created SSH tunnel', True, localcmdsudoprefix +
                                             "ps -ef | grep ssh | grep %s | awk {'print $2'}" %
                                             swapped_ip, show_log=show_log).split()[0]
                # add pid entry to table
                # 'tunnel_pid': None
                if show_log:
                    debug("SSH Tunnel PID is %s(tun%s)" % (ssh_tunnel_pid, targettunnel_id))
                tunnels[targettunnel_id]['tunnel_pid'] = str(ssh_tunnel_pid)
                tunnels[targettunnel_id]['tunnel_active'] = True
                break
            if retry_cnt == 5:
                error("Giving up...")
                cleanup()

        # Provision remote tun interface
        run_sys_cmd("Setting IP on remote tun adapter", False, sshbasecmd +
                    "'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" %
                    (targettunnel_id, targettunnel_id), show_log=show_log)

        # Check if we need the return route re-adding or not
        return_routes = run_sys_cmd("Check if we need the return route re-adding or not", False, sshbasecmd +
                                    "'ip route list dev tun%s 10.%s.254.2/32'" % (targettunnel_id, targettunnel_id), show_log=show_log)
        if return_routes == '':
            # Add return route back to us
            run_sys_cmd("Adding return route back to us", False, sshbasecmd +
                        "'sudo route add 10.%s.254.2 dev tun%s'" %
                        (targettunnel_id, targettunnel_id), show_log=show_log)

        # Turn up our interface
        run_sys_cmd("Turn up our interface", True, localcmdsudoprefix +
                    "ifconfig tun%s up" % targettunnel_id, show_log=show_log)

        # Provision interface
        run_sys_cmd("Provision interface", True, localcmdsudoprefix +
                    "ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (targettunnel_id,
                                                                            targettunnel_id), show_log=show_log)
        time.sleep(2)

        # Allow local connections to the proxy server
        run_sys_cmd("Allow connections to our proxy servers", True, localcmdsudoprefix +
                    "iptables -t nat -I POSTROUTING -d %s -j RETURN" % swapped_ip, show_log=show_log)

        # NAT outbound traffic going through our tunnels
        run_sys_cmd("NAT outbound traffic going through our tunnels", True, localcmdsudoprefix +
                    "iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " %
                    targettunnel_id, show_log=show_log)

        # re-enable the route
        tunnels[targettunnel_id]['route_active'] = True
        # Rebuild Route table
        nexthopcmd = "ip route replace default scope global "
        for tunnel_id, tunnel in tunnels.items():
            # don't include the host we are tearing down in the multipath routing or any others that have been disabled
            if tunnel['route_active'] and tunnel['tunnel_active'] and tunnel['link_state_active']:
                nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight 1 " % (tunnel_id, tunnel_id)
                # As we are using multipath routing and will do route cache-busting elsewhere
                # it is (probably?) good enough to do ECMP here (i.e. weight = 1 for all routes)
            else:
                if show_log:
                    debug("Tunnel tun%s is not suitable so not including in route table. (Route %s - Tunnel %s - Link %s)" %
                          (tunnel_id, str(tunnel['route_active']), str(tunnel['tunnel_active']),
                           str(tunnel['link_state_active'])))

        run_sys_cmd("Insert custom route (rotate_host)", True, localcmdsudoprefix + nexthopcmd, show_log=show_log)

    else:
        error("New IP address has not been found - not configuring (tun%s)" % targettunnel_id)


########################################################################################################################
# thread_handler for Rotate Hosts to decouple the process flow and the process logic
########################################################################################################################
def rotate_host_thread_handler():
    num_thread_workers = floor(args.num_of_instances / 2)
    if num_thread_workers < 1:
        num_thread_workers = 1
    while not exit_threads:
        with futures.ThreadPoolExecutor(num_thread_workers) as rotate_host_executor:
            rotate_host_futures = []
            for tunnel_id, tunnel in tunnels.items():
                rotate_host_futures.append(rotate_host_executor.submit(rotate_host, targettunnel_id=tunnel_id))


########################################################################################################################
# Perform cache-busting on ECMP routing
########################################################################################################################
def cache_bust(show_log=True):
    # we do random route weight here to force variation in the use of the multipath routes
    # Rebuild Route table
    nexthopcmd = "ip route replace default scope global "
    weights = range(1, args.num_of_instances + 1)
    if show_log:
        debug("The range of weights to give to routes are: %s" % str(weights))
    # generate a random int between 1 and the num of interfaces +1 to be the weight of the route as this is using
    # random.sample the values should not be repeated and we will never have ECMP routing
    random_weights = random.sample(weights, args.num_of_instances)
    if show_log:
        debug("The route weights have been ordered as: %s" % str(random_weights))
    for tunnel_id, tunnel in tunnels.items():
        # only include the tunnel that are marked as active in the non-ECMP routing
        if tunnel['tunnel_active'] and tunnel['route_active'] and tunnel['link_state_active']:
            nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight %s " % \
                         (tunnel_id, tunnel_id, random_weights[tunnel_id])
        else:
            debug("Tunnel tun%s is not suitable so not including in route table" % tunnel_id)
    run_sys_cmd("Insert custom route (cache_bust)", True, localcmdsudoprefix + nexthopcmd, show_log=show_log)
    # sleep for half a second to help ensure the subsequent cache flush doesn't happen before the route as been applied
    # there is apparent bias in this mechanism for one route over the others and it isn't clear as to what the cause is
    # hoping that it is just a race condition
    time.sleep(0.5)
    run_sys_cmd("Flushing route cache", True, localcmdsudoprefix + 'ip route flush cache', show_log=show_log)


########################################################################################################################
# thread_handler for cache_bust to decouple the process flow and the process logic
########################################################################################################################
def cache_bust_thread_handler():
    while True:
        # check if the exit flag has been set
        if exit_threads:
            exit()
        cache_bust(show_log=False)
        time.sleep(2)


########################################################################################################################
# Check OS reported state of tunnel
########################################################################################################################
def tunnel_is_up(target_tunnel_id, show_log=False):
    state = run_sys_cmd('Get status of the interface', True,
                        'cat /sys/class/net/tun%s/operstate' % target_tunnel_id, report_errors=False, show_log=show_log)
    if state.rstrip() == "up":
        return True
    else:
        return False


########################################################################################################################
# Check OS reported state of tunnel
########################################################################################################################
def tunnel_health_monitor_thread_handler():
    update_needed = False
    # we are in a separate thread so keep going till program close
    while True:
        # check if the exit flag has been set
        if exit_threads:
            exit()

        # cycle through all known tunnels
        for target_tunnel_id in tunnels:
            # get the tunnel's status
            target_tunnel_is_up = tunnel_is_up(target_tunnel_id, show_log=False)
            # Do stuff if the link is not happy
            if target_tunnel_is_up != tunnels[target_tunnel_id]['link_state_active']:
                tunnels[target_tunnel_id]['link_state_active'] = not tunnels[target_tunnel_id]['link_state_active']
                update_needed = True
                if target_tunnel_is_up:
                    success('Tunnel tun%s has come back up' % target_tunnel_id)
                else:
                    tunnels[target_tunnel_id]['link_state_active'] = False
                    warning('Tunnel tun%s has been detected as down' % target_tunnel_id)
            # check to see if we have a thread doing cache busting
            if not args.b and update_needed:
                # if not, we need to update routes
                nexthopcmd = "ip route replace default scope global "
                for tunnel_id, tunnel in tunnels.items():
                    # only include the tunnel that are marked as active in the ECMP routing
                    if tunnel['tunnel_active'] and tunnel['route_active'] and tunnel['link_state_active']:
                        nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight 1 " % \
                                     (tunnel_id, tunnel_id)
                run_sys_cmd("Insert custom route (tunnel_health_monitor)", True,
                            localcmdsudoprefix + nexthopcmd, show_log=False)
                # update is no longer needed so reset the flag
                update_needed = False

        time.sleep(1)


########################################################################################################################
# Get Interface IP
########################################################################################################################
def get_ip_address(ifname):
    ip = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
    debug(ip)
    return ip


########################################################################################################################
# Get Default Route
########################################################################################################################
def get_default_gateway_linux():
    gws = netifaces.gateways()
    gwip = gws['default'][netifaces.AF_INET][0]
    debug(gwip)
    return gwip


########################################################################################################################
# The main event
########################################################################################################################
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
    instances = conn.get_only_instances(filters={"tag:Name": nameTag, "instance-state-name": "running"})
    public_ips = ''
    tunnel_id = 0
    for instance in instances:
        tunnels[tunnel_id] = {'cloud_id': instance.id, 'pub_ip': instance.ip_address,
                              'tunnel_pid': None, 'route_active': False,
                              'tunnel_active': False, 'link_state_active': True}
        public_ips = public_ips + instance.ip_address + " "
        tunnel_id += 1
    debug("Public IP's for all instances: %s" % public_ips)

    # Create ssh Tunnels for proxying
    success("Provisioning Hosts.....")
    for tunnel_id, tunnel in tunnels.items():
        log(tunnel['pub_ip'])
        sshbasecmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s " % (
            homeDir, keyName, tunnel['pub_ip'])

        # Enable Tunneling on the remote host
        run_sys_cmd("Enabling tunneling via SSH on %s (tun%s)" % (tunnel['pub_ip'], tunnel_id), False, sshbasecmd +
                    "'echo \"PermitTunnel yes\" | sudo tee -a  /etc/ssh/sshd_config'")

        # Restarting Service to take new config (you'd think a simple reload would be enough)
        run_sys_cmd("Restarting Service to take new config on %s (tun%s)" % (tunnel['pub_ip'], tunnel_id), False, sshbasecmd +
                    "'sudo service ssh restart'")

        # Provision interface
        run_sys_cmd("Provisioning tun%s interface on %s" % (tunnel_id, tunnel['pub_ip']), False, sshbasecmd +
                    "'sudo ip tuntap add dev tun%s mode tun'" % tunnel_id)

        # Configure interface
        run_sys_cmd("Configuring tun%s interface on %s" % (tunnel_id, tunnel['pub_ip']), False, sshbasecmd +
                    "'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" % (tunnel_id, tunnel_id))

        # Enable forwarding on remote host
        run_sys_cmd("Enable forwarding on remote host (tun%s)" % tunnel_id, False, sshbasecmd + "'sudo su root -c \"echo 1 > "
                                                                            "/proc/sys/net/ipv4/ip_forward\"'")

        # Provision iptables on remote host
        run_sys_cmd("Provision iptables on remote host (tun%s)" % tunnel_id, False, sshbasecmd + "'sudo iptables -t nat -A POSTROUTING "
                                                                             "-o eth0 -j MASQUERADE'")

        # Add return route back to us
        run_sys_cmd("Add return route back to us (tun%s)" % tunnel_id, False, sshbasecmd + "'sudo route add 10.%s.254.2 dev tun%s'"
                    % (tunnel_id, tunnel_id))

        # Create tun interface
        run_sys_cmd("Creating local interface tun%s" % str(tunnel_id), True, localcmdsudoprefix +
                    "ip tuntap add dev tun%s mode tun" % str(tunnel_id))

        # Turn up our interface
        run_sys_cmd("Turning up interface tun%s" % str(tunnel_id), True, localcmdsudoprefix +
                    "ifconfig tun%s up" % tunnel_id)

        # Provision interface
        run_sys_cmd("Assigning interface tun" + str(tunnel_id) + " ip of 10." + str(tunnel_id) + ".254.2", True,
                    localcmdsudoprefix + "ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (tunnel_id, tunnel_id))
        time.sleep(0.5)

        # Establish tunnel interface
        sshcmd = "ssh -i %s/.ssh/%s.pem -w %s:%s -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o " \
                 "ServerAliveInterval=50 ubuntu@%s &" % \
                 (homeDir, keyName, tunnel_id, tunnel_id, tunnel['pub_ip'])
        debug("SHELL CMD (remote): " + sshcmd)
        retry_cnt = 0
        while retry_cnt < 6:
            retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
            if retcode != 0:
                warning("Failed to establish ssh tunnel on %s. Retrying..." % tunnel['pub_ip'])
                retry_cnt = retry_cnt + 1
                time.sleep(1)
            else:
                ssh_tunnel_pid = run_sys_cmd('Getting PID of newly created SSH tunnel', True, localcmdsudoprefix +
                                             "ps -ef | grep ssh | grep %s | awk {'print $2'}" %
                                             tunnel['pub_ip']).split()[0]
                # add pid entry to table
                # 'tunnel_pid': None
                debug("SSH Tunnel PID is %s" % ssh_tunnel_pid)
                tunnels[tunnel_id]['tunnel_pid'] = str(ssh_tunnel_pid)
                # mark tunnel as active
                tunnels[tunnel_id]['tunnel_active'] = True
                break
            if retry_cnt == 5:
                error("Giving up...")
                cleanup()

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

    # do routing and ip tables for each of the tunnel hosts, including build the ECMP route
    nexthopcmd = "ip route replace default scope global "
    for tunnel_id, tunnel in tunnels.items():
        # Allow connections to our proxy servers
        run_sys_cmd("Allowing connections to our proxy servers", True, localcmdsudoprefix +
                    "iptables -t nat -I POSTROUTING -d %s -j RETURN" % tunnel['pub_ip'])

        # NAT outbound traffic going through our tunnels
        run_sys_cmd("NAT outbound traffic that goes through our tunnels", True, localcmdsudoprefix +
                    "iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " % tunnel_id)

        # Build ECMP route table command
        nexthopcmd = nexthopcmd + "nexthop via 10.%s.254.1 dev tun%s weight 1 " % (tunnel_id, tunnel_id)

        # Mark route as active
        tunnels[tunnel_id]['route_active'] = True

        # Add static routes for our SSH tunnels
        run_sys_cmd("Adding static routes for our SSH tunnels", True, localcmdsudoprefix +
                    "ip route add %s via %s dev %s" % (tunnel['pub_ip'], defaultgateway, networkInterface))

    # Replace default route with the new default route
    run_sys_cmd("Replace default route with the new default route", True, localcmdsudoprefix + "%s" % nexthopcmd)

    success("Done!")
    print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("+ Leave this terminal open and start another to run your commands.   +")
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    print("[" + bcolors.WARNING + "~" + bcolors.ENDC + "] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC +
          " to terminate the script gracefully.")


########################################################################################################################
# System and Program Arguments
########################################################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-id', '--image-id', nargs='?', default='ami-d05e75b8',
                    help="Amazon ami image ID.  Example: ami-d05e75b8. If not set, ami-d05e75b8.")
parser.add_argument('-t', '--image-type', nargs='?', default='t2.nano',
                    help="Amazon ami image type Example: t2.nano. If not set, defaults to t2.nano.")
parser.add_argument('--region', nargs='?', default='us-east-1',
                    help="Select the region: Example: us-east-1. If not set, defaults to us-east-1.")
parser.add_argument('-r', action='store_true', help="Enable Rotating AMI hosts.")
parser.add_argument('-b', action='store_true', help="Enable multipath cache busting.")
parser.add_argument('-m', action='store_true', help="Disable the link state monitor thread.")
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
# define the internal data structure here so that it is globally accessible
# tunnels[tunnel_id] = {'cloud_id': instance.id, 'pub_ip': instance.ip_address, 'tunnel_pid': None, 'route_active':
#                                  False, 'tunnel_active': False, link_state_active: False}
tunnels = {}
exit_threads = False

########################################################################################################################
# Sanity Checks and set up
########################################################################################################################
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
    if not args.m:
        tunnel_health_monitor_thread = threading.Thread(target=tunnel_health_monitor_thread_handler, daemon=True)
        tunnel_health_monitor_thread.start()
    else:
        warning('Disabling the link state monitor')
    # threading is only required for cache_bust() if we are also going to rotate_host()
    if args.b and args.r:
        success("Launching multipath cache busting")
        cache_bust_thread = threading.Thread(target=cache_bust_thread_handler, daemon=True)
        cache_bust_thread.start()
        success("Launching tunnel IP rotator")
        rotate_host_thread = threading.Thread(target=rotate_host_thread_handler, daemon=True)
        rotate_host_thread.start()
    # deal with stuff that isn't threaded
    while True:
        # handle cache_bust() if not running rotate_host()
        if args.b and not args.r:
            success("performing multipath cache bust")
            cache_bust()
        # handle rotate_host() in any circumstance
        if args.r and not args.b:
            success("Rotating infrastructure IPs.")

            # loop round detected instances of each reservation
            for tunnel_id, tunnel in tunnels.items():
                rotate_host(tunnel_id)
        # the below sleep is just to stop wild things from happening until proper timing control is implemented.
        time.sleep(5)
