#! /usr/bin/python3

import argparse
import os
import sys
import logging
import subprocess
import re

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

action_to_check = [
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
]
action_list = ['*']
for action in action_to_check:
    n = 4
    while n < len(action):
        action_list.append(f"{action[0:n]}*")
        n = n + 1
    if n == len(action):
        action_list.append(f"{action[0:n]}")
action_list = list(dict.fromkeys(action_list))

resource_regex_strings = [
    "^\\*$",
    "arn:aws:\\*$"
]

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

    # Script Operations Arguments
    parser.add_argument('--verbose', action='store_true', default=False, help=f"Report output every step of the way.")
    parser.add_argument('-r', '--roles', action='store_true', default=False, help='Only check IAM Roles.')
    parser.add_argument('-u', '--users', action='store_true', default=False, help='Only check IAM Users.')
    parser.add_argument('-ug', '--unused-groups', action='store_true', default=False, help='Print unused groups that are overpermissive.')
    parser.add_argument('-sh', '--show-header', action='store_true', default=False, help='Print header row with output.')
    
    return parser.parse_args()


def get_profiles(profiles):
    """
    Runs "aws configure" to find regex matching for profiles list
    """
    valid_profiles = []
    for profile in profiles:
        command = f"aws configure list-profiles".split(' ')
        result = subprocess.run(command, capture_output=True)
        stdout_output = result.stdout.decode("utf-8").split('\n')
        reg = re.compile(profile)
        for p in stdout_output:
            res = reg.match(p)
            if res:
                valid_profiles.append(res.string)
    if not valid_profiles:
        logging.error(f"No profiles found with provided string \"{profiles}\".")
        sys.exit()
    
    return valid_profiles


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
        if ARGS.verbose:
            logging.info(f"[+] Validated BOTO3 Session for Account #{ACCOUNT_ID}")
    except ClientError as error:
        logging.error(error)
        sys.exit()


##################
# Script Functions
##################

def find_overpermissive_policies():
    """
    Find potentially overly permissive policies in use
    """
    iam_client = SESSION.client('iam', config=CONFIG)
    
    results = {}
    if ARGS.users or (not ARGS.users and not ARGS.roles):
        # Get user details
        all_user_data = get_user_data(iam_client)

        # Get group details
        all_group_data = get_group_data(iam_client)
        
        # Check policies
        user_group_results = check_user_policy_statement(all_user_data, all_group_data)
        results = {**results, **user_group_results}


    if ARGS.roles or (not ARGS.users and not ARGS.roles):
        # Get role details
        all_role_data = get_role_data(iam_client)

        # Check policies
        role_results = check_role_policy_statement(all_role_data)
        results = {**results, **role_results}
    
    # Print results
    report_results(results)


def get_user_data(iam_client):
    """
    Build user policies (attached+inline) and group membership
    """
    all_user_details = []
    try:
        resp = iam_client.list_users()
        users = [a.get("UserName") for a in resp.get("Users")]
        marker = resp.get('Marker', None)
        while marker:
            resp = iam_client.list_users(Marker=marker)
            new_users = [a.get("UserName") for a in resp.get("Users")]
            users.extend(new_users)
            marker = resp.get('Marker', None)

        for user in users:
            user_details = {'user_name': user, 'groups': None,
                             'attached': [], 'inline': []}

            # get attached user policies (managed policies)
            resp = iam_client.list_attached_user_policies(UserName=user)
            attached_user_policy_arns = [a.get('PolicyArn') for a in resp.get('AttachedPolicies', '')]
            for policy_arn in attached_user_policy_arns:
                resp = iam_client.get_policy(PolicyArn=policy_arn)
                policy_name = resp.get('Policy','').get('PolicyName')
                policy_version = resp.get('Policy').get('DefaultVersionId')
                resp = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
                statement = resp.get('PolicyVersion','').get('Document','').get('Statement','')
                statment = statement if isinstance(statement, list) else [statement]
                user_details['attached'].append({'name': policy_name,
                                                 'policy_arn': policy_arn,
                                                 'version': policy_version,
                                                 'statement': statement})

            # get user policies (inline policies)
            resp = iam_client.list_user_policies(UserName=user)
            user_policy_names = resp.get('PolicyNames', '')
            for inline_policy in user_policy_names:
                resp = iam_client.get_user_policy(UserName=user, PolicyName=inline_policy)
                statement = resp.get('PolicyDocument','').get('Statement','')
                statment = statement if isinstance(statement, list) else [statement]
                user_details['inline'].append({'name': resp.get('PolicyName'),
                                               'policy_arn': inline_policy,
                                               'statement': statment})
            all_user_details.append(user_details)

            resp = iam_client.list_groups_for_user(UserName=user)
            user_details['groups'] = [a.get('GroupName') for a in resp.get('Groups')]
        return all_user_details
    except ClientError as error:
        pass


def get_group_data(iam_client):
    """
    Build group policies (attached+inline)
    """
    all_group_details = []
    try:
        resp = iam_client.list_groups()
        groups = [a.get("GroupName") for a in resp.get("Groups")]
        marker = resp.get('Marker', None)
        while marker:
            resp = iam_client.list_roles(Marker=marker)
            groups.extend([a.get("GroupName") for a in resp.get("Groups")])
            marker = resp.get('Marker', None)

        for group in groups:
            group_details = {'group_name': group, 'attached': [], 'inline': []}

            # get attached group policies
            resp = iam_client.list_attached_group_policies(GroupName=group)
            attached_group_policy_arns = [a.get('PolicyArn') for a in resp.get('AttachedPolicies', '')]
            for policy_arn in attached_group_policy_arns:
                resp = iam_client.get_policy(PolicyArn=policy_arn)
                policy_name = resp.get('Policy','').get('PolicyName')
                policy_version = resp.get('Policy').get('DefaultVersionId')
                resp = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
                statement = resp.get('PolicyVersion','').get('Document','').get('Statement','')
                statement = statement if isinstance(statement, list) else [statement]
                group_details['attached'].append({'name': policy_name,
                                                  'policy_arn': policy_arn,
                                                  'version': policy_version,
                                                  'statement': statement})

            # get group policies (inline policies)
            resp = iam_client.list_group_policies(GroupName=group)
            group_policy_names = resp.get('PolicyNames', '')
            for inline_policy in group_policy_names:
                resp = iam_client.get_group_policy(GroupName=group, PolicyName=inline_policy)
                statement = resp.get('PolicyDocument','').get('Statement','')
                statement = statement if isinstance(statement, list) else [statement]
                group_details['inline'].append({'name': resp.get('PolicyName'),
                                                'policy_arn': inline_policy,
                                                'statement': statement})
            all_group_details.append(group_details)
        return all_group_details
    except ClientError as error:
        pass


def get_role_data(iam_client):
    """
    Get role policies (attached+inline)
    """
    all_role_details = []
    try:
        resp = iam_client.list_roles()
        roles = [a.get("RoleName") for a in resp.get("Roles")]
        marker = resp.get('Marker', None)
        while marker:
            resp = iam_client.list_roles(Marker=marker)
            roles.extend([a.get("RoleName") for a in resp.get("Roles")])
            marker = resp.get('Marker', None)

        for role in roles:
            role_details = {'role_name': role, 'attached': [], 'inline': []}

            # get attached role policies
            resp = iam_client.list_attached_role_policies(RoleName=role)
            attached_role_policy_arns = [a.get('PolicyArn') for a in resp.get('AttachedPolicies', '')]
            for policy_arn in attached_role_policy_arns:
                resp = iam_client.get_policy(PolicyArn=policy_arn)  
                policy_name = resp.get('Policy','').get('PolicyName')
                policy_version = resp.get('Policy').get('DefaultVersionId')
                resp = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
                statement = resp.get('PolicyVersion').get('Document','').get('Statement','')
                statement = statement if isinstance(statement, list) else [statement]
                role_details['attached'].append({'name': policy_name,
                                                 'policy_arn': policy_arn,
                                                 'version': policy_version,
                                                 'statement': statement})

            # get role policies (inline policies)
            resp = iam_client.list_role_policies(RoleName=role)
            role_policy_names = resp.get('PolicyNames', '')
            for inline_policy in role_policy_names:
                resp = iam_client.get_role_policy(RoleName=role, PolicyName=inline_policy)
                statement = resp.get('PolicyDocument','').get('Statement','')
                statement = statement if isinstance(statement, list) else [statement]
                role_details['inline'].append({'name': resp.get('PolicyName'),
                                               'policy_arn': inline_policy,
                                               'statement': statement})
            all_role_details.append(role_details)
        return all_role_details
    except ClientError as error:
        pass


def check_user_policy_statement(all_user_data, all_group_data):
    """
    Check if statements are overly permissive
    """
    flagged_group_policies = []
    flagged_user_policies = []
    user_assigned_groups = []
    
    # review policies for groups - needed for user review later
    for group_data in all_group_data:
        for attached_data in group_data.get('attached'):
            if analyze_policy(attached_data.get('statement')):
                flagged_group_policies.append({'group_name': group_data.get('group_name'),
                                               'policy_arn': attached_data.get('policy_arn'),
                                               'flagged_policy': attached_data.get('name'),
                                               'source': 'attached_policy'})
        for inline_data in group_data.get('inline'):
            if analyze_policy(inline_data.get('statement')):
                flagged_group_policies.append({'group_name': group_data.get('group_name'),
                                               'policy_arn': inline_data.get('policy_arn'),
                                               'flagged_policy': inline_data.get('name'),
                                               'source': 'inline_policy'})

    # review policies for users, including group details
    for user_data in all_user_data:
        for group_name in user_data.get('groups'):
            matching_groups = [a for a in flagged_group_policies if group_name == a.get('group_name')]
            for group in matching_groups:
            # if group_name in [a.get('group_name') for a in flagged_group_policies]:
                user_assigned_groups.append(group_name)
                flagged_user_policies.append({'user_name': user_data.get('user_name'),
                                              'policy_arn': group.get('policy_arn'),
                                              'flagged_policy': group.get('flagged_policy'),
                                              'source': f'group_({group_name})'})

        for attached_data in user_data.get('attached'):
            if analyze_policy(attached_data.get('statement')):
                flagged_user_policies.append({'user_name': user_data.get('user_name'),
                                              'policy_arn': attached_data.get('policy_arn'),
                                              'flagged_policy': attached_data.get('name'),
                                              'source': 'managed_policy'})

        for inline_data in user_data.get('inline'):
            if analyze_policy(inline_data.get('statement')):
                flagged_user_policies.append({'user_name': user_data.get('user_name'),
                                              'policy_arn': inline_data.get('policy_arn'),
                                              'flagged_policy': inline_data.get('name'),
                                              'source': 'inline_policy'})

    unused_groups = [a for a in flagged_group_policies if a.get('group_name') not in user_assigned_groups]
    return {'flagged_user_policies': flagged_user_policies,
            'flagged_group_policies': unused_groups}


def check_role_policy_statement(all_role_data):
    """
    Check if statements are overly permissive
    """
    flagged_role_policies = []
    user_assigned_groups = []
    
    # review policies for roles
    for role_data in all_role_data:
        for attached_data in role_data.get('attached'):
            if analyze_policy(attached_data.get('statement')):
                flagged_role_policies.append({'role_name': role_data.get('role_name'),
                                              'policy_arn': attached_data.get('policy_arn'),
                                              'flagged_policy': attached_data.get('name'),
                                              'source': 'managed_policy'})

        for inline_data in role_data.get('inline'):
            if analyze_policy(inline_data.get('statement')):
                flagged_role_policies.append({'role_name': role_data.get('role_name'),
                                              'policy_arn': inline_data.get('policy_arn'),
                                              'flagged_policy': inline_data.get('name'),
                                              'source': 'inline_policy'})

    return {'flagged_role_policies': flagged_role_policies}


def analyze_policy(statement):
    """
    Analyze polict json
    """

    for entry in statement:
        action_status = False
        not_action_status = False
        resource_status = False

        if isinstance(entry.get('Action'), str):
            entry['Action'] = [entry.get('Action')]
        if isinstance(entry.get('Resource'), str):
            entry['Resource'] = [entry.get('Resource')]

        if 'Action' in entry:
            if entry.get('Effect') == 'Allow':
                for action in entry.get('Action'):
                    if action in action_list:
                        action_status = True
                        break
                    if action_status:
                        break

            if action_status:
                for rescource in entry.get('Resource'):
                    for reg_string in resource_regex_strings:
                        if re.search(reg_string, rescource, re.IGNORECASE):
                            resource_status = True
                            break

        return True if (action_status and resource_status) else False


def report_results(combined_results):
    """
    Report results however is appropriate
    """
    # Print Header
    if PROFILES.index(PROFILE) == 0 and ARGS.show_header and (ARGS.users or ARGS.roles or (not ARGS.users and not ARGS.roles)):
        print("profile,account_id,type,identity_name,source,policy_arn")

    identity_types = ['user', 'role']
    if ARGS.unused_groups:
        identity_types.append('group')
    
    for identity in identity_types:
        all_results = combined_results.get(f'flagged_{identity}_policies','')
        for results in sorted(all_results, key=lambda d: d['source']):
            name = results.get(f'{identity}_name')
            source = results.get('source')
            arn = results.get('policy_arn')
            iden = identity
            if ARGS.unused_groups and identity == 'group':
                iden = iden + "_(unused)"
            print(f"{PROFILE},{ACCOUNT_ID},{iden},{name},{source},{arn}")


###############
# Main Function
###############

if __name__ == '__main__':
    # Process CLI Arguments
    global ARGS
    ARGS = parse_cli_args()

    global PROFILES 
    PROFILES = get_profiles(ARGS.profiles)
    for profile in PROFILES:
        # Setup and validate session to work from
        boto_session_setup(profile)

        # Do the thing
        find_overpermissive_policies()
