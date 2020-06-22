import requests
import json
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from urllib.parse import parse_qsl, urljoin, urlparse
import boto3
import botocore


#########
# Get Akamai CIDR for all maps,
#########

def akamai_getcidr():
    edgerc = EdgeRc('~/.edgerc')      # Update the path to you edgrc, use complete path 
    section = 'default'               # if your edgerc has default section
    baseurl = 'https://%s' % edgerc.get(section, 'host')

    s = requests.Session()
    s.auth = EdgeGridAuth.from_edgerc(edgerc, section)

    result = s.get(urljoin(baseurl, '/siteshield/v1/maps'))
    data = result.json()

    cidrArray = []
    for Cidrs in data["siteShieldMaps"]:
        cidrArray.extend(Cidrs["currentCidrs"])

    # To get unique values from the retrieved list hence converting to a set
    return(set(cidrArray))


##########
# So check all security groups having a TAG SecureCIDRs and value Akamai AutoUpdate
##########

def describe_security_groups():
    grpName=[]
    try:
        response = client.describe_security_groups(Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'RequestExpired':
            print('Your AWS keys have expired or invalid. More details below')
            raise(error.response)
        else:
            print("Un-Handled Exception:", error.response, "I gave up")
            raise (error.response)
            exit(1)


    for groupname in response['SecurityGroups']:
            if ('GroupName' in groupname):
                #print("The result is",groupname['GroupName'])
                grpName.append(groupname['GroupName'])
    return (set(grpName))


#########
# Get CIDR already added, so we can update (add or delete), Just to make sure we are using correct groupname and tags
#########

def get_cidronSG( loopgrpname ):
    cidr_sg = []
    response = client.describe_security_groups(GroupNames=[loopgrpname],Filters=[{'Name': 'tag:SecureCIDRs', 'Values': ['Akamai AutoUpdate']}])
    for iprange in response['SecurityGroups']:
        for IpPermissions in  iprange['IpPermissions']:
            for cidr in IpPermissions['IpRanges']:
                if ('Description' in cidr) and ( cidr['Description'] == "Akamai SiteShield" ):
                    cidr_sg.append(cidr['CidrIp'])
    return (set(cidr_sg))


#########
#  This does the dirty work of updating all
#########

def update_security_groups():
    #ec2 = boto3.client('ec2')
    akamai_cidr = akamai_getcidr()
    print("The akamai_cidr", akamai_cidr)

    groupName = describe_security_groups()
    print("The groups that has the tag: ",groupName)

    #print("Now processing comparision")
    #toadd=akamai_cidr.difference(cidr_sg)
    #print(toadd)

    #todel=cidr_sg.difference(akamai_cidr)
    #print(todel)


    # Now processing adding new Security groups to all Security Group have tags
    for loopgrpname in groupName:
        print("Currently processing Cider_sg: ", loopgrpname)
        cidr_sg = get_cidronSG(loopgrpname)

        toadd = akamai_cidr.difference(cidr_sg)
        print("Adding CIDR",toadd," to Security Group",loopgrpname)
        print("in Security Group",cidr_sg)

        for cidradd in toadd:
            try:
                response = client.authorize_security_group_ingress(GroupName=loopgrpname, IpPermissions=[
                    {'FromPort': 443, 'IpProtocol': 'tcp', 'ToPort': 443,
                     'IpRanges': [{'CidrIp': cidradd, 'Description': 'Akamai SiteShield'}]}])
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                    print('Ignoring as it already exists')
                else:
                    print(error.response)

    # Now processing Deleteing (Akamai periodically removes CIDR which might be vunerable )
    #for loopgrpname in groupName:
        todel = cidr_sg.difference(akamai_cidr)
        print("Removing CIDR",todel," from Security Group",loopgrpname)

        for cidradd in todel:
            try:
                response = client.revoke_security_group_ingress(GroupName=loopgrpname, IpPermissions=[
                    {'FromPort': 443, 'IpProtocol': 'tcp', 'ToPort': 443,
                     'IpRanges': [{'CidrIp': cidradd, 'Description': 'Akamai SiteShield'}]}])
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                    print('Ignoring not found')
                else:
                   print(error.response)

##
# Main Program starts here
##

client = boto3.client('ec2')
update_security_groups() # TO do add ingress ports



