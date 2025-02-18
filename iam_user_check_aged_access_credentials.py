#! /usr/bin/python3

import argparse
import os
import sys
import logging
import xlsxwriter
import pandas as pd
import numpy as np
import re
import subprocess
import matplotlib.pyplot as plt
import datetime

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
    parser.add_argument('-p', '--profiles', nargs='+', default=['default'], help="Specify profile or regex to match in credentials file to use. Defaults to 'default'.")

    # Script Operations Arguments
    parser.add_argument('--verbose', action='store_true', default=False, help=f"Report output every step of the way.")
    parser.add_argument('-f', "--report-format", nargs='+', default=['xlsx'], help="Specify report format (csv, xlsx, png). Defaults to xlsx")
    parser.add_argument('-o', '--output-path', default=PWD, help='Specify output path. Defaults to PWD')
    parser.add_argument('-c', '--column-width', default=2.5, type=float, help='Specify the column width for PNG output. Defaults to 2.5')
    parser.add_argument('-d', '--days-ago', default=0, type=int, help='The number of days ago threshold to compare against. Defaults to 0')

    global ARRRRRGS
    ARRRRRGS = parser.parse_args()

    # Make sure profile name is passed
    if not ARRRRRGS.profiles:
        logging.error(f"Profile(s) to use was not provided.")
        sys.exit()


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
        logging.error(f"No profiles found with provided string.")
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

    boto3.set_stream_logger(name='botocore.credentials', level=logging.WARNING)
    sts_session = SESSION.client('sts')
    global ACCOUNT_ID
    try:
        boto3.set_stream_logger(name='botocore.credentials', level=logging.WARNING)
        ACCOUNT_ID = sts_session.get_caller_identity().get("Account")
        # logging.info(f"[+] Validated BOTO3 Session for Account #{ACCOUNT_ID} ({profile})")
    except ClientError as error:
        logging.error(error)
        return False
    return True


##################
# Script Functions
##################

def check_aged_access():
    """
    Check IAM users in a given AWS account to see if any of the following has occured
        1. IAM User password is older than 90 days or more
        2. IAM User last activity is older than 90 days or more
        3. IAM Users Access Keys are older than 90 days or more
    Save report-friendly output for any accounts that fail these checks
    """
    global IAM_CLIENT
    IAM_CLIENT = SESSION.client('iam')
    
    users = IAM_CLIENT.list_users()
    users = [a.get('UserName','') for a in users.get('Users',[])]

    user_data = {}
    past_date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=ARRRRRGS.days_ago)
    for user in users:
        # Check password existance and age
        user_data[user] = check_pass_age(user, past_date)

        # Check last activity and create age
        user_data[user].update(check_activity_and_create(user, past_date))
    return user_data


def check_pass_age(user, past_date):
    """
    Get password age details for user and return details we care about
    pass_age_check: True = Passed, False = Failed
        If no password, then pass
        If password and activity less than 90 days, then pass
        If password and activity greater or equal to 90 days, then fail
    """
    record = {'has_password': False, 'pass_age_check': False, 'pass_age_days': -1}
    try:
        # Check if password exists for user
        login_prof = IAM_CLIENT.get_login_profile(UserName=user)
        if 'LoginProfile' in login_prof:
            last_login_date = login_prof.get('LoginProfile','').get('CreateDate','').replace(tzinfo=datetime.timezone.utc)
        else:
            return record
        record['has_password'] = True
        record['pass_age_days'] = abs((past_date - last_login_date).days)
        # Check if password is greater or equal to threshold
        if last_login_date and (past_date <= last_login_date):
            record['pass_age_check'] = True
    except ClientError as error:
        record['pass_age_check'] = True
    return record


def check_activity_and_create(user, past_date):
    """
    Get last activity date and check if within range we care about
    if activity_check fails, then False
    if key_create_check fails, then False
    """
    record = {'key_data': [], 'console_login': False, 'activity_check': False, 'activity_check_days':-1, 'key_create_check': False, 'created':-1}

    # Get access key last use dates
    access_keys = []
    try:
        num = 0
        keys = IAM_CLIENT.list_access_keys(UserName=user)
        for key in keys.get('AccessKeyMetadata'):
            key_create_age = key.get('CreateDate').replace(tzinfo=datetime.timezone.utc)
            key_create_days = (datetime.datetime.now(datetime.UTC) - key_create_age).days
            access_keys.append({'key_num': num, 'key_id': key.get('AccessKeyId'),
                                'create_date': key_create_age, 'create_days': key_create_days})
            num += 1
    except ClientError as error:
        pass

    try:
        for key_data in access_keys:
            key_last_used_age = IAM_CLIENT.get_access_key_last_used(AccessKeyId=key_data.get('key_id'))
            key_last_used_age = key_last_used_age.get('AccessKeyLastUsed','').get('LastUsedDate','')
            if key_last_used_age:
                key_data['key_last_used_age'] = key_last_used_age
                key_data['key_last_used_days'] = (datetime.datetime.now(datetime.UTC) - key_data['key_last_used_age']).days
                record['key_data'].append(key_data)
    except ClientError as error:
        pass

    # Get console login last use date
    try:
        user_details = IAM_CLIENT.get_user(UserName=user).get('User','')
        if 'PasswordLastUsed' in user_details:
            last_used = user_details.get('PasswordLastUsed').replace(tzinfo=datetime.timezone.utc)
            record['console_login'] = last_used
    except ClientError as error:
        pass

    # Check if lastest activity is within threshold
    key_last_used_data = [a.get('key_last_used_age') for a in record['key_data']]
    last_activity = key_last_used_data + [record['console_login']] if record['console_login'] else key_last_used_data
    record['activity_check_days'] = (datetime.datetime.now(datetime.UTC) - max(last_activity)).days if last_activity else "Never"
    if last_activity and (past_date <= max(last_activity)):
        record['activity_check'] = True

    # Check if key age is within threshold
    key_create_ages = [a.get('create_date').replace(tzinfo=datetime.timezone.utc) for a in record['key_data']]
    if key_create_ages and (past_date <= max(key_create_ages)):
        record['key_create_check'] = True

    # Account Create Date
    create_date = user_details.get('CreateDate').replace(tzinfo=datetime.timezone.utc)
    created = (datetime.datetime.now(datetime.UTC) - create_date).days
    if created >= 365:
        created = f'{int(created / 365)} years ago'
    elif created > 30 and created < 365:
        created = f'{int(created / 30)} months ago'
    else:
        created = f'{created} days ago'
    record['created'] = created
    
    return record


def save_results(records):
    """
    Save results to file or output as desired
    """
    for report_format in ARRRRRGS.report_format:
        if report_format == "xlsx":
            xlsx_report(records)
        if report_format == "csv":
            csv_report(records)
        if report_format == "png":
            png_report(records)


def xlsx_report(records):
    """
    Output xlsx format
    """
    # create workbook
    date = datetime.datetime.now().strftime('%d-%m-%Y')
    workbook = xlsxwriter.Workbook(f"{ARRRRRGS.output_path}/iam_user_checks_{date}.xlsx")
    row, col = 0, 0
    
    # Add findings for password - if password exists and password >= 90 days
    worksheet = workbook.add_worksheet('password_check')
    password_findings = [('account','user','days')]
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if data.get('has_password') and not data.get('pass_age_check'):
                password_findings.append((acct_id, user, data.get('pass_age_days')))
    for account, user, days in password_findings:
        worksheet.write(row, col, account)
        worksheet.write(row, col+1, user)
        worksheet.write(row, col+2, days)
        row += 1
        
    # Add findings for activity age - if last activity >= 90 days
    worksheet = workbook.add_worksheet('activity_check')
    activity_findings = [('account','user','lastActivity','created')]
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if not data.get('activity_check'):
                activity_findings.append((acct_id, user, data.get('activity_check_days'), data.get('created')))
    row = 1
    for account, user, activity, created in activity_findings:
        worksheet.write(row, col, account)
        worksheet.write(row, col+1, user)
        worksheet.write(row, col+2, activity)
        worksheet.write(row, col+3, created)
        row += 1

    # Add findings for access key age - if access key age >= n days
    worksheet = workbook.add_worksheet('access_keys_check')
    access_key_findings = [('account','user','key1','key2')]
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if data.get('key_data'):
                key1 = data.get('key_data')[0].get('create_days')
                key2 = data.get('key_data')[1].get('create_days') if len(data.get('key_data')) == 2 else "N/A"
                access_key_findings.append((acct_id, user, key1, key2))
    row = 1
    for account, user, key1, key2 in access_key_findings:
        worksheet.write(row, col, account)
        worksheet.write(row, col+1, user)
        worksheet.write(row, col+2, key1)
        worksheet.write(row, col+3, key2)
        row += 1

    workbook.close()


def csv_report(records):
    """
    Just a simple means to report the checks. May not keep.
    """
    messages = ['acctId', 'user'] 
    keys = ['has_password', 'pass_age_check', 'pass_age_days', 'activity_check', 'activity_check_days', 'key_create_check', 'created']
    messages = [messages + keys]

    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            message = [acct_id, user]
            for key in keys:
                message.append(str(data[key]))
            messages.append(message)
    for line in messages:
        print(','.join(line))


def png_report(records):
    """
    Save to png graph
    """
    # Save Password PNG
    accounts = []
    users = []
    days = []
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if data.get('has_password') and not data.get('pass_age_check'):
                accounts.append(ACCOUNT_ID)
                users.append(user)
                days.append(data.get('pass_age_days'))
    df = pd.DataFrame(data=dict(account=accounts, user=users, days=days))
    fig,ax = render_mpl_table(df, header_columns=0, col_width=ARRRRRGS.column_width)
    fig.savefig(f"{ARRRRRGS.output_path}/password_age_check.png")
    
    # Save Activity PNG
    accounts = []
    users = []
    days = []
    created = []
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if not data.get('activity_check'):
                accounts.append(ACCOUNT_ID)
                users.append(user)
                days.append(data.get('activity_check_days'))
                created.append(data.get('created'))
    df = pd.DataFrame(data=dict(account=accounts, user=users, days=days))
    fig,ax = render_mpl_table(df, header_columns=0, col_width=ARRRRRGS.column_width)
    fig.savefig(f"{ARRRRRGS.output_path}/activity_age_check.png")

    # Save Access Key PNG
    accounts = []
    users = []
    keys1 = []
    keys2 = []
    for acct_id, user_data in records.items():
        for user, data in user_data.items():
            if not data.get('activity_check') and data.get('key_data'):
                accounts.append(ACCOUNT_ID)
                users.append(user)
                keys1.append(data.get('key_data')[0].get('key_last_used_days'))
                keys2.append(data.get('key_data')[1].get('key_last_used_days') if len(data.get('key_data')) == 2 else "N/A")
    df = pd.DataFrame(data=dict(account=accounts, user=users, keys1=keys1, keys2=keys2))
    fig,ax = render_mpl_table(df, header_columns=0, col_width=ARRRRRGS.column_width)
    fig.savefig(f"{ARRRRRGS.output_path}/access_key_age_check.png")


def render_mpl_table(data, col_width=3.0, row_height=0.625, font_size=14,
                     header_color='#40466e', row_colors=['#f1f1f2', 'w'], edge_color='w',
                     bbox=[0, 0, 1, 1], header_columns=0,
                     ax=None, **kwargs):
    """
    print output as a PNG image
    https://stackoverflow.com/questions/19726663/how-to-save-the-pandas-dataframe-series-data-as-a-figure
    """                     
    if ax is None:
        size = (np.array(data.shape[::-1]) + np.array([0, 1])) * np.array([col_width, row_height])
        fig, ax = plt.subplots(figsize=size)
        ax.axis('off')
    mpl_table = ax.table(cellText=data.values, bbox=bbox, colLabels=data.columns, **kwargs)
    mpl_table.auto_set_font_size(False)
    mpl_table.set_fontsize(font_size)

    for k, cell in mpl_table._cells.items():
        cell.set_edgecolor(edge_color)
        if k[0] == 0 or k[1] < header_columns:
            cell.set_text_props(weight='bold', color='w')
            cell.set_facecolor(header_color)
        else:
            cell.set_facecolor(row_colors[k[0]%len(row_colors) ])
    return ax.get_figure(), ax


###############
# Main Function
###############

if __name__ == '__main__':
    # Process CLI Arguments
    parse_cli_args()

    records = {}
    profiles = get_profiles(ARRRRRGS.profiles)
    for profile in profiles:

        # Setup and validate session to work from
        session_state = boto_session_setup(profile)

        # Do the thing
        if session_state:
            records[ACCOUNT_ID] = check_aged_access()

    # Report findings
    save_results(records)
