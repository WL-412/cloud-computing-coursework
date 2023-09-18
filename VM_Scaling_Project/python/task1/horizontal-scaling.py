
import boto3
import botocore
import os
import requests
import time
import json
import configparser
import re
from dateutil.parser import parse
import datetime
from bs4 import BeautifulSoup



########################################
# Constants
########################################
with open('horizontal-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']

# Credentials fetched from environment variables
SUBMISSION_USERNAME = os.environ['SUBMISSION_USERNAME']
SUBMISSION_PASSWORD = os.environ['SUBMISSION_PASSWORD']

ec2 = boto3.resource('ec2', region_name='us-east-1')

########################################
# Tags
########################################

def convert_to_tags(tag_pairs):
    return [{'Key': k, 'Value': v} for k, v in tag_pairs]

# Load Generator Tags
LG_TAG_PAIRS = [
    ("Project", "vm-scaling"),
    ("Name", "P1 load generator")
]

# Web Service Tags
WS_TAG_PAIRS = [
    ("Project", "vm-scaling"),
    ("Name", "P1 web service")
]

LG_TAGS = convert_to_tags(LG_TAG_PAIRS)
WS_TAGS = convert_to_tags(WS_TAG_PAIRS)


TEST_NAME_REGEX = r'name=(.*log)'

########################################
# Utility functions
########################################


def create_instance(ami, sg_id, tags):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_id: ID of the security group to be attached to instance
    :return: instance object
    """
    instance = None

    # TODO: Create an EC2 instance
    # Wait for the instance to enter the running state
    # Reload the instance attributes

    # ec2 = boto3.client('ec2')

    # Create the EC2 instance
    response = ec2.create_instances(
        ImageId=ami,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_id],  # Attach the security group
        InstanceType=INSTANCE_TYPE,  # Specify instance type as needed
        KeyName='my_key_pair',  # Specify your key pair
    )

    # Get the instance ID of the newly created instance
    instance_id = response[0].id

    # Reload the instance attributes
    instance = ec2.Instance(instance_id)

    # Wait for the instance to enter the running state
    instance.wait_until_running()

    instance.create_tags(Tags=tags)

    return instance

def create_security_group(group_name, permissions):
    # Check if security group with this name already exists
    ec2_client = boto3.client('ec2')
    security_groups = ec2_client.describe_security_groups(Filters=[
        {
            'Name': 'group-name',
            'Values': [group_name]
        }
    ])['SecurityGroups']

    if security_groups:
        print(f"Security group {group_name} already exists.")
        return security_groups[0]['GroupId']
    
    security_group = ec2.create_security_group(
        GroupName=group_name,
        Description='Security Group for ' + group_name
        )
    security_group.authorize_ingress(IpPermissions=permissions)
    return security_group.id

def initialize_test(lg_dns, first_web_service_dns):
    """
    Start the horizontal scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/test/horizontal?dns={}'.format(
        lg_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                log_link = soup.find('a')['href']
                log_file_name = log_link.split('=')[-1]
                return log_file_name
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    return None

def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


def is_test_complete(lg_dns, log_name):
    """
    Check if the horizontal scaling test has finished
    :param lg_dns: load generator DNS
    :param log_name: name of the log file
    :return: True if Horizontal Scaling test is complete and False otherwise.
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    log_text = requests.get(log_string).text
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


def add_web_service_instance(lg_dns, sg2_name, log_name):
    """
    Launch a new WS (Web Server) instance and add to the test
    :param lg_dns: load generator DNS
    :param sg2_name: name of WS security group
    :param log_name: name of the log file
    """
    ins = create_instance(WEB_SERVICE_AMI, sg2_name, WS_TAGS)
    print("New WS launched. id={}, dns={}".format(
        ins.instance_id,
        ins.public_dns_name)
    )
    add_req = 'http://{}/test/horizontal/add?dns={}'.format(
        lg_dns,
        ins.public_dns_name
    )
    while True:
        if requests.get(add_req).status_code == 200:
            print("New WS submitted to LG.")
            break
        elif is_test_complete(lg_dns, log_name):
            print("New WS not submitted because test already completed.")
            break


def authenticate(lg_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param lg_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """

    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        lg_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass


def get_rps(lg_dns, log_name):
    """
    Return the current RPS as a floating point number
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: latest RPS value
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    config = configparser.ConfigParser(strict=False)
    config.read_string(requests.get(log_string).text)
    sections = config.sections()
    sections.reverse()
    rps = 0
    for sec in sections:
        if 'Current rps=' in sec:
            rps = float(sec[len('Current rps='):])
            break
    return rps


def get_test_start_time(lg_dns, log_name):
    """
    Return the test start time in UTC
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: datetime object of the start time in UTC
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    start_time = None
    while start_time is None:
        config = configparser.ConfigParser(strict=False)
        config.read_string(requests.get(log_string).text)
        # By default, options names in a section are converted
        # to lower case by configparser
        start_time = dict(config.items('Test')).get('starttime', None)
    return parse(start_time)


########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Provision resources to achieve horizontal scalability
    #   - Create security groups for Load Generator and Web Service
    #   - Provision a Load Generator instance
    #   - Provision a Web Service instance
    #   - Register Web Service DNS with Load Generator
    #   - Add Web Service instances to Load Generator
    #   - Terminate resources

    print_section('1 - create two security groups')
    sg_permissions = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # TODO: Create two separate security groups and obtain the group ids
    sg1_id = create_security_group("Load Generator Security Group", sg_permissions)  # Security group for Load Generator instances
    sg2_id = create_security_group("Web Service Security Group", sg_permissions)  # Security group for Web Service instances

    print_section('2 - create LG')

    # TODO: Create Load Generator instance and obtain ID and DNS
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id, LG_TAGS)
    lg_id = lg.id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    # TODO: Create First Web Service Instance and obtain the DNS
    ws_instance = create_instance(WEB_SERVICE_AMI, sg2_id, WS_TAGS)
    web_service_dns = ws_instance.public_dns_name

    print_section('4. Submit the first WS instance DNS to LG, starting test.')
    log_name = initialize_test(lg_dns, web_service_dns)
    last_launch_time = get_test_start_time(lg_dns, log_name)
    start_time = get_test_start_time(lg_dns, log_name)
    RPS_THRESHOLD = 50
    MAX_TEST_DURATION = 30
    COOLDOWN_PERIOD = 100
    while not is_test_complete(lg_dns, log_name):
        # TODO: Check RPS and last launch time
        # TODO: Add New Web Service Instance if Required
        current_rps = get_rps(lg_dns, log_name)
        current_time = datetime.datetime.utcnow()
        last_launch_time_naive = last_launch_time.replace(tzinfo=None)
        time_since_last_launch = current_time - last_launch_time_naive

        start_time_naive = start_time.replace(tzinfo=None)
        test_duration = current_time - start_time_naive

        if test_duration > datetime.timedelta(minutes=MAX_TEST_DURATION):
            print("Test exceeded the maximum duration of 30 minutes.")
            break  

        if current_rps > RPS_THRESHOLD:
            print("Current RPS exceeded the RPS threshold.")
            break  

        if time_since_last_launch > datetime.timedelta(seconds=COOLDOWN_PERIOD):
            add_web_service_instance(lg_dns, sg2_id, log_name)
            last_launch_time = current_time
        time.sleep(1)

    print_section('End Test')

    # TODO: Terminate Resources
    lg.terminate()

    web_service_instances = ec2.instances.filter(Filters=[{
        'Name': 'instance.group-id',
        'Values': [sg2_id]
    }])

    for instance in web_service_instances:
        instance.terminate()


if __name__ == '__main__':
    main()