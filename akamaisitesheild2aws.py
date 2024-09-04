import requests
import json
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from urllib.parse import parse_qsl, urljoin, urlparse
import boto3
import botocore

# Create an EC2 client
ec2 = boto3.client('ec2')

#########
# Get Akamai CIDR for all maps,
#########

def akamai_getcidr():
    """
    Get Akamai CIDR blocks for all maps.

    Returns:
        set: A set of Akamai CIDR blocks.
    """
    try:
        edgerc = EdgeRc('~/.edgerc')  # Update the path to your edgerc, use complete path
        section = 'default'  # if your edgerc has default section
        baseurl = 'https://%s' % edgerc.get(section, 'host')

        s = requests.Session()
        s.auth = EdgeGridAuth.from_edgerc(edgerc, section)

        result = s.get(urljoin(baseurl, '/siteshield/v1/maps'))
        result.raise_for_status()  # Raise an exception for bad status codes
        data = result.json()

        cidr_array = []
        for cidrs in data["siteShieldMaps"]:
            cidr_array.extend(cidrs["currentCidrs"])

        # To get unique values from the retrieved list hence converting to a set
        return set(cidr_array)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

##########
# So check all security groups having a TAG SecureCIDRs and value Akamai AutoUpdate
##########

def describe_security_groups():
    """
    Describe all security groups with the tag SecureCIDRs and value Akamai AutoUpdate.

    Returns:
        set: A set of security group names.
    """
    try:
        response = ec2.describe_security_groups(Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
        group_names = [group['GroupName'] for group in response['SecurityGroups']]
        while 'NextToken' in response:
            response = ec2.describe_security_groups(NextToken=response['NextToken'], Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
            group_names.extend([group['GroupName'] for group in response['SecurityGroups']])
        return set(group_names)
    except botocore.exceptions.ClientError as e:
        print(f"An error occurred: {e}")
        return None

#########
# Get CIDR already added, so we can update (add or delete), Just to make sure we are using correct groupname and tags
#########

def get_cidronSG(group_name):
    """
    Get the CIDR blocks for a security group.

    Args:
        group_name (str): The name of the security group.

    Returns:
        set: A set of CIDR blocks.
    """
    try:
        response = ec2.describe_security_groups(GroupNames=[group_name], Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
        cidr_sg = []
        for ip_range in response['SecurityGroups']:
            for ip_permissions in ip_range['IpPermissions']:
                for cidr in ip_permissions['IpRanges']:
                    if ('Description' in cidr) and (cidr['Description'] == "Akamai SiteShield"):
                        cidr_sg.append(cidr['CidrIp'])
        while 'NextToken' in response:
            response = ec2.describe_security_groups(NextToken=response['NextToken'], GroupNames=[group_name], Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
            for ip_range in response['SecurityGroups']:
                for ip_permissions in ip_range['IpPermissions']:
                    for cidr in ip_permissions['IpRanges']:
                        if ('Description' in cidr) and (cidr['Description'] == "Akamai SiteShield"):
                            cidr_sg.append(cidr['CidrIp'])
        return set(cidr_sg)
    except botocore.exceptions.ClientError as e:
        print(f"An error occurred: {e}")
        return None

#########
#  This does the dirty work of updating all
#########

def update_security_groups():
    """
    Update all security groups with the latest Akamai CIDR blocks.
    """
    akamai_cidr = akamai_getcidr()
    print("The akamai_cidr", akamai_cidr)

    group_names = describe_security_groups()
    print("The groups that has the tag: ", group_names)

    for group_name in group_names:
        print("Updating security group: ", group_name)
        current_cidr = get_cidronSG(group_name)
        print("Current CIDR: ", current_cidr)

        # Remove existing CIDR blocks
        for cidr in current_cidr:
            try:
                ec2.revoke_security_group_ingress(GroupName=group_name, IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': cidr, 'Description': 'Akamai SiteShield'}]}])
            except botocore.exceptions.ClientError as e:
                print(f"An error occurred: {e}")

        # Add new CIDR blocks
        for cidr in akamai_cidr:
            try:
                ec2.authorize_security_group_ingress(GroupName=group_name, IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': cidr, 'Description': 'Akamai SiteShield'}]}])
            except botocore.exceptions.ClientError as e:
                print(f"An error occurred: {e}")

    print("Security groups updated successfully")


# Main Code.
update_security_groups()
