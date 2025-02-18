#! /usr/bin/python3

import argparse
import os
import sys
import logging
import itertools
import subprocess
import re

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

HOME = os.path.expanduser("~")
PWD = os.getcwd()
DELAY = 1
logging.basicConfig(level=logging.INFO,
                    format = "%(asctime)s %(message)s",
                    datefmt = '%Y-%m-%d %H:%M:%S',
                    handlers=[logging.StreamHandler()])

ACCOUNT_ID = None
CONFIG = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

##############
# Script Setup
##############

def parse_cli_args():
    """
    Process and validate command-line arguments
    """
    parser = argparse.ArgumentParser(prog='find_open_security_groups', description='Will search for and report "open" security groups.')
    
    # AWS Credentials Arguments
    parser.add_argument('--credentials_file', default=HOME + '/.aws/credentials',
                        help=f"Location of AWS Credentials file. Defaults to {HOME + '/.aws/credentials'}")
    parser.add_argument('-p', '--profiles', nargs='+', default=[], help="Specify a single or a list of profiles in csv format to match in credentials file to use.")
    parser.add_argument('-pr', '--profiles-regex', default="", help="Specify a regex string to match in from 'aws configure list-profiles' output.")
    parser.add_argument('--regions', nargs='+', default=["all-regions"], help="Specify a single or multiple regions. 'all-regions' will check allregions. \
                                                      Defaults to value in credentials file then all-regions.")    

    # Script Operations Arguments
    parser.add_argument('--verbose', action='store_true', default=False, help=f"Report output every step of the way.")
    parser.add_argument('-o', '--ports', help='Specific ports to check for. Can specify "any" for all.',
                        nargs='+', type=str, default=[22, 53, 135, 139, 389, 445, 1433, 3389, 5423])
    parser.add_argument('-r', '--remove-column', nargs='+', default=[], help='Remove columns from output. (account,region,group_id,protocol,ports,ipv4,ipv6,attached,public_ips,instance_id)')
    parser.add_argument('-a', '--show-all', action='store_true', default=False, help='Output all Security Groups, including those not currently in use.')
    parser.add_argument('-sa', '--sum-attachments', action='store_true', default=False, help='Sum list of attachments instead printing all.')
    parser.add_argument('-se', '--sum-external-ips', action='store_true', default=False, help='Sum list of external IPs instead printing all.')
    parser.add_argument('-e', '--external-ips-only', action='store_true', default=False, help='Only include Security Groups in used with External IPs in output.')
    parser.add_argument('-c', '--compress-ports', action='store_true', default=False, help='Compress ports from multiple entries into one section to reduce output.')
    parser.add_argument('-sh', '--show-header', action='store_true', default=False, help='Print header columns with output.')
    
    global ARRRRRGS
    ARRRRRGS = parser.parse_args()

    # Make sure profiles-regex matches configured profiles
    if ARRRRRGS.profiles_regex:
        cmd = "aws configure list-profiles".split(" ")
        result = subprocess.Popen(cmd, stdout=subprocess.PIPE ,encoding='utf8')
        available_profiles = result.stdout.read().splitlines()
        matched_profiles = []
        for prof in available_profiles:
            if re.search(ARRRRRGS.profiles_regex, prof):
                matched_profiles.append(prof)
        if matched_profiles:
            ARRRRRGS.profiles = sorted(matched_profiles)
        else:
            logging.error(f"Profiles-Regex did not match any configured profiles")
            sys.exit()
    if not ARRRRRGS.profiles:
        logging.error(f"Profile(s) was not provided.")
        sys.exit()

    # Validate Ports
    if type(ARRRRRGS.ports[0]) == "str":
        if ',' in ARRRRRGS.ports[0]:
            ARRRRRGS.ports = ARRRRRGS.ports[0].split(',')
            all_ports = []
            for port in ARRRRRGS.ports:
                if '-' in port:
                    p_range = port.split('-')
                    all_ports = all_ports + range(p_range[0], p_range[1])
                else:
                    all_ports.append(port)
                ARRRRRGS.ports = all_ports
            ARRRRRGS.ports = sorted([int(a) for a in ARRRRRGS.ports if a.isdigit() and a > 0 and a <= 65535])
        if 'any' in (port.lower() for port in ARRRRRGS.ports):
            ARRRRRGS.ports = 'any'
    elif type(ARRRRRGS.ports[0]) == "int":
        pass

def boto_session_setup(profile):
    """
    1. Create session for boto to work off of
    2. Validate legitimate access
    """

    session_details = {"profile_name": profile,
                       "region_name":  'us-east-1'}

    global SESSION
    SESSION = boto3.session.Session(**session_details)

    sts_session = SESSION.client('sts')
    global PROFILE
    PROFILE = profile
    global ACCOUNT_ID
    try:
        ACCOUNT_ID = sts_session.get_caller_identity().get("Account")
        if ARRRRRGS.verbose:
            logging.info(f"[+] Validated BOTO3 Session for Account #{ACCOUNT_ID}")
    except ClientError as error:
        logging.error(error)
        sys.exit()

    # Update regions now that session is verified
    all_regions = sorted(SESSION.get_available_regions('ec2'))
    if 'all-regions' in ARRRRRGS.regions:
        ARRRRRGS.regions = all_regions
    else:
        for region in ARRRRRGS.regions:
            if region not in all_regions:
                logging.error(f"[!] {region} is not a valid region.Region List: {all_regions}")
                sys.exit()



##################
# Script Functions
##################

def find_open_sgs():
    """
    Find Security Groups that are more open than they may need to be
    """
    records = []
    region_sgs = get_region_sgs()
    for region, sgs in region_sgs.items():
        for sg in sgs:
            ip_permissions = sg.get('IpPermissions')
            group_id = sg.get('GroupId')
            sg_records = []
            for ip in ip_permissions:
                from_port = ip.get('FromPort')
                to_port = ip.get('ToPort')
                # These values aren't included in data if they're set to "All"
                if not from_port:
                    from_port = 1
                if not to_port:
                    to_port = 65535

                ipv4_ranges = [a.get('CidrIp') for a in ip['IpRanges']]
                ipv6_ranges = [a.get('CidrIpv6') for a in ip['Ipv6Ranges']]
                flagged = False

                if check_ports(from_port, to_port):
                    flagged = check_ips(ipv4_ranges, ipv6_ranges)

                if flagged:
                    protocol = "All traffic" if ip.get('IpProtocol') == "-1" else ip.get('IpProtocol')
                    ipv4_ranges = ';'.join(ipv4_ranges) if len(ipv4_ranges) > 0 else ''
                    ipv6_ranges = ';'.join(ipv6_ranges) if len(ipv6_ranges) > 0 else ''
                    ports = [f"{from_port}"] if from_port == to_port else [f"{from_port}-{to_port}"]
                    sg_records.append({'ports': ports, 'protocol': protocol, 'ipv4_ranges': ipv4_ranges, 'ipv6_ranges': ipv6_ranges})

            if sg_records:
                details = {'region': region,'group_id': group_id, 'details': sg_records}
                match = False
                # check for attachments
                interface_ids, public_ips, instance_ids = check_attachments(region, sg)

                details['instance_id'] = instance_ids if instance_ids else ''
                if ARRRRRGS.show_all or (not ARRRRRGS.show_all and interface_ids):
                    details['interface_ids'] = interface_ids if interface_ids else ''
                    match = True
                if (not ARRRRRGS.external_ips_only and match) or (ARRRRRGS.external_ips_only and public_ips and match):
                    details['public_ips'] = public_ips if public_ips else ''
                    match = True
                else:
                    match = False
                
                if match:
                    records.append(details)

    if ARRRRRGS.compress_ports:
        records = compress_ports(records)

    report_results(records)


def get_region_sgs():
    """
    Get Security Groups from each region
    """
    region_sgs = {}
    for region in ARRRRRGS.regions:
        ec2_client = SESSION.client('ec2', region_name=region, config=CONFIG)
        try:
            sgs = ec2_client.describe_security_groups()
            region_sgs[region] = sgs.get('SecurityGroups') if 'SecurityGroups' in sgs else sgs
        except ClientError as error:
            pass
    return region_sgs


def check_ports(from_port, to_port):
    """
    Check if ports are in the list to watch for
    """
    if 'any' in ARRRRRGS.ports:
        return True
    if [a for a in range(from_port, to_port+1) if a in ARRRRRGS.ports]:
        return True
    return False


def check_ips(ipv4_ranges, ipv6_ranges):
    """
    Check if IPs are defined too broadly
    """
    if any([True for a in ipv4_ranges if '0.0.0.0/0' or '::/0' in a]):
        return True
    if any([True for a in ipv6_ranges if '0.0.0.0/0' or '::/0' in a]):
        return True


def check_attachments(region, sg):
    """
    Check if SGs are attached anywhere
    """
    try:
        ec2_client = SESSION.client('ec2', region_name=region, config=CONFIG)
        associations = ec2_client.describe_network_interfaces(
            Filters = [{'Name': 'group-id', 'Values': [sg.get('GroupId')]}])
        associations = associations.get('NetworkInterfaces')
        # attachments = associations.get('Attachment').get('InstanceId')
    except ClientError as error:
        associations = []

    public_ips = [a.get('Association').get('PublicIp') for a in associations if a.get('Association')]
    interface_ids = [a.get('NetworkInterfaceId') for a in associations]
    instance_ids = [a.get('Attachment').get('InstanceId', '') for a in associations if a.get('Attachment')]
    return (interface_ids, public_ips, instance_ids)


def compress_ports(records):
    """
    Compress ports from multiple lines into one line
    """
    new_records = []
    for record in records:
        tracker = []
        for details in record.get('details'):
            if not tracker:
                tracker.append(details)
            else:
                found = False
                for item in tracker:
                    if details['protocol'] == item['protocol'] and details['ipv4_ranges'] == item['ipv4_ranges'] and details['ipv6_ranges'] == item['ipv6_ranges']:
                        item['ports'] = item.get('ports') + details['ports']
                        found = True
                if not found:
                    tracker.append(details)
        for item in tracker:
            ports = [explode_ranges(a) for a in item.get('ports')][0]
            item['ports'] = list_to_ranges(sorted(ports, key=int))
        record['details'] = tracker
    return records


def explode_ranges(port_range):
    """
    Converts a string in format 'x-y' into list of integers
    """
    element = port_range.split('-')
    if len(element) == 1:
        return [int(''.join(element))]
    elif len(element) == 2:
        return [a for a in range(int(element[0]), int(element[1])+1)]


def list_to_ranges(lst):
    """
    Convert list of integers into list of ranges of integers
    """
    lst_len = len(lst)
    result = []
    scan = 0
    while lst_len - scan > 2:
        step = lst[scan + 1] - lst[scan]
        if lst[scan + 2] - lst[scan + 1] != step:
            result.append(f"{lst[scan]}")
            scan += 1
            continue

        for j in range(scan+2, lst_len-1):
            if lst[j+1] - lst[j] != step:
                result.append(f"{lst[scan]}-{lst[j]}")
                scan = j+1
                break
        else:
            result.append(f"{lst[scan]}-{lst[j]+1}")
            return result

    if lst_len - scan == 1:
        result.append(str(lst[scan]))
    elif lst_len - scan == 2:
        result.append(','.join(itertools.imap(str, lst[scan:])))

    return result


def report_results(records):
    """
    Print results out
    """
    columns = ['profile', 'account', 'region', 'group_id', 'protocol', 'ports', 'ipv4', 'ipv6', 'attached', 'public_ips', 'instance_id']
    header = ",".join([a for a in columns if a not in ARRRRRGS.remove_column])    
    if ARRRRRGS.show_header and ARRRRRGS.profiles.index(PROFILE) == 0:
        print(header)
    if not records:
        print(f"{PROFILE},{ACCOUNT_ID}" + (",'N/A'" * int(len(header.split(','))-2)))
    for record in records:
        for detail in record['details']:
            message = ""
            if 'profile' not in ARRRRRGS.remove_column:
                message += f"{PROFILE},"
            if 'account' not in ARRRRRGS.remove_column:
                message += f"{ACCOUNT_ID},"
            if 'region' not in ARRRRRGS.remove_column:
                message += f"{record.get('region')},"
            if 'group_id' not in ARRRRRGS.remove_column:
                message += f"{record.get('group_id')},"
            if 'protocol' not in ARRRRRGS.remove_column:
                message += f"{detail.get('protocol')},"
            if 'ports' not in ARRRRRGS.remove_column:
                message += f"{';'.join(detail.get('ports'))},"
            if 'ipv4' not in ARRRRRGS.remove_column:
                message += f"{detail.get('ipv4_ranges')},"
            if 'ipv6' not in ARRRRRGS.remove_column:
                message += f"{detail.get('ipv6_ranges')},"
            if 'attached' not in ARRRRRGS.remove_column:
                if ARRRRRGS.sum_attachments:
                    attachments = len(record.get('interface_ids'))
                elif not ARRRRRGS.sum_attachments and len(record.get('interface_ids')) == 0:
                    attachments = "None"
                else:
                    attachments = ';'.join(record.get('interface_ids'))
                message += f"{attachments},"
            if 'public_ips' not in ARRRRRGS.remove_column:
                if ARRRRRGS.sum_external_ips:
                    public_ips = len(record.get('public_ips')) 
                elif not ARRRRRGS.sum_external_ips and len(record.get('public_ips')) == 0:
                    public_ips = "None"
                else:
                    public_ips = ';'.join(record.get('public_ips'))
                message += f"{public_ips},"
            if 'instance_id' not in ARRRRRGS.remove_column:
                message += f"{';'.join(record.get('instance_id'))},"
            print(message[:-1])


###############
# Main Function
###############

if __name__ == '__main__':
    # Process CLI Arguments
    parse_cli_args()

    records = {}
    acct_map = {}
    for profile in ARRRRRGS.profiles:
        # Setup and validate session to work from
        boto_session_setup(profile)

        # Do the thing
        records[ACCOUNT_ID] = find_open_sgs()
