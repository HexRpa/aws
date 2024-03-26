import boto3
import pandas as pd
from openpyxl.utils import get_column_letter
import os
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

session = boto3.Session(profile_name='default')

# Initialize boto3 clients
ec2_client = session.client('ec2')
rds_client = session.client('rds')
dynamodb = session.client('dynamodb')
iam_client = session.client('iam')
glue_client = session.client('glue')

logging.info("Configuration loaded successfully.")

def get_nacl_rules():
    nacls = ec2_client.describe_network_acls()
    nacl_data = []
    for nacl in nacls['NetworkAcls']:
        nacl_id = nacl['NetworkAclId']
        for entry in nacl['Entries']:
            # Checking if the rule is inbound or outbound
            rule_direction = 'inbound' if entry['Egress'] == False else 'outbound'
            
            # Creating a record for each rule
            nacl_data.append({
                'NACL ID': nacl_id,
                'Rule Number': entry['RuleNumber'],
                'Protocol': entry['Protocol'],
                'Rule Action': entry['RuleAction'],
                'CIDR Block': entry['CidrBlock'],
                'Direction': rule_direction,
                'Port Range': entry.get('PortRange', {}).get('From', 'All') if entry.get('PortRange') else 'All'
            })
    
    # Convert list of dicts to a DataFrame
    return pd.DataFrame(nacl_data)

def get_security_group_rules():
    sg_rules_data = []
    security_groups = ec2_client.describe_security_groups()

    for sg in security_groups['SecurityGroups']:
        sg_id = sg['GroupId']
        
        # Process ingress rules
        for rule in sg['IpPermissions']:
            sg_rules_data.append({
                'Security Group ID': sg_id,
                'Security Group Rule ID': rule.get('IpPermissionId', 'N/A'),  # Not all rules have a distinct ID
                'IP Version': 'IPv4',  # Defaulting to IPv4; adjust based on your needs or rule specifics
                'Type': 'ingress',
                'Protocol': rule['IpProtocol'],
                'Port Range': f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}" if rule.get('FromPort') else 'All',
                'Source': ', '.join([ip['CidrIp'] for ip in rule.get('IpRanges', [])] + [ip['GroupId'] for ip in rule.get('UserIdGroupPairs', [])])
            })
        
        # Process egress rules
        for rule in sg['IpPermissionsEgress']:
            sg_rules_data.append({
                'Security Group ID': sg_id,
                'Security Group Rule ID': rule.get('IpPermissionId', 'N/A'),
                'IP Version': 'IPv4',  # Adjust as needed
                'Type': 'egress',
                'Protocol': rule['IpProtocol'],
                'Port Range': f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}" if rule.get('FromPort') else 'All',
                'Source': ', '.join([ip['CidrIp'] for ip in rule.get('IpRanges', [])] + [ip['GroupId'] for ip in rule.get('UserIdGroupPairs', [])])
            })

    return pd.DataFrame(sg_rules_data)

def get_route_tables():
    route_tables_data = []
    route_tables = ec2_client.describe_route_tables()

    for rt in route_tables['RouteTables']:
        rt_id = rt['RouteTableId']
        vpc_id = rt['VpcId']

        # Associations (Subnets and NACLs)
        # Note: Route tables don't directly associate with NACLs in AWS. NACLs are associated with subnets.
        associations = rt.get('Associations', [])
        associated_subnets = [assoc['SubnetId'] for assoc in associations if assoc.get('SubnetId')]
        
        # Fetching each route in the route table
        for route in rt['Routes']:
            destination = route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock') or 'N/A'
            target = route.get('GatewayId') or route.get('NatGatewayId') or route.get('TransitGatewayId') or route.get('VpcPeeringConnectionId') or 'N/A'
            
            # Compiling route table details
            route_tables_data.append({
                'Route Table ID': rt_id,
                'VPC ID': vpc_id,
                'Associated Subnets': ', '.join(associated_subnets),
                'Destination': destination,
                'Target': target
            })

    return pd.DataFrame(route_tables_data)

def get_iam_roles():
    roles_response = iam_client.list_roles()
    role_data = []
    for role in roles_response['Roles']:
        # Fetch attached policies for each role (optional)
        attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])
        policies = [policy['PolicyName'] for policy in attached_policies['AttachedPolicies']]
        
        role_data.append({
            'Role Name': role['RoleName'],
            'Role ID': role['RoleId'],
            'ARN': role['Arn'],
            'Creation Date': role['CreateDate'],
            'Attached Policies': ', '.join(policies)
        })
    roles_df = pd.DataFrame(role_data)
    
    # Sort by 'Creation Date' descending
    roles_df = roles_df.sort_values(by='Creation Date', ascending=False)
    
    # Convert 'Creation Date' to string format for Excel output
    roles_df['Creation Date'] = roles_df['Creation Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return roles_df

def get_glue_jobs():
    glue_jobs = glue_client.get_jobs()
    job_data = []
    for job in glue_jobs['Jobs']:
        job_data.append({
            'Job Name': job['Name'],
            'Job Type': job.get('Command', {}).get('Name', 'N/A'),  # Assuming Command.Name as Job Type
            'Creation Time': job['CreatedOn'].strftime('%Y-%m-%d %H:%M:%S') if 'CreatedOn' in job else 'N/A',
            'Last Modified Time': job['LastModifiedOn'].strftime('%Y-%m-%d %H:%M:%S') if 'LastModifiedOn' in job else 'N/A',
        })
    return job_data

# Function to fetch EC2 instances
def get_ec2_instances():
    instances = ec2_client.describe_instances()
    instance_data = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            # Fetching Security Group Names
            sg_names = [sg['GroupName'] for sg in instance.get('SecurityGroups', [])]

            instance_data.append({
                'Instance ID': instance['InstanceId'],
                'Type': instance['InstanceType'],
                'State': instance['State']['Name'],
                'Public IP': instance.get('PublicIpAddress', 'N/A'),
                'Private IP': instance.get('PrivateIpAddress', 'N/A'),  # Include private IP
                'Subnet ID': instance.get('SubnetId', 'N/A'),
                'Security Groups': ", ".join(sg_names)
            })
    return pd.DataFrame(instance_data)



# Function to fetch RDS instances
def get_rds_instances():
    instances = rds_client.describe_db_instances()
    instance_data = []
    for instance in instances['DBInstances']:
        # Fetching Security Group Names
        sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
        sg_names = []  # Placeholder for security group names if implementing name fetching

        # Publicly accessible status
        is_publicly_accessible = instance['PubliclyAccessible']
        
        endpoint_address = instance.get('Endpoint', {}).get('Address', 'N/A')  # Endpoint for both private and public connectivity
        # Note: RDS does not provide separate attributes for public and private IPs like EC2 instances do.
        # The endpoint address is used for connectivity, and whether it's public or private depends on the instance settings.

        instance_data.append({
            'DB Instance Identifier': instance['DBInstanceIdentifier'],
            'DB Instance Class': instance['DBInstanceClass'],
            'Engine': instance['Engine'],
            'DB Instance Status': instance['DBInstanceStatus'],
            'Endpoint Address': endpoint_address,
            'Publicly Accessible': 'Yes' if is_publicly_accessible else 'No',
            'Security Groups': ", ".join(sg_names)
        })
    return pd.DataFrame(instance_data)

def get_security_group_names_by_ids(sg_ids):
    sg_names = []
    if sg_ids:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        sg_names = [sg['GroupName'] for sg in response['SecurityGroups']]
    return sg_names

# Function to fetch Subnets
def get_subnets():
    subnets = ec2_client.describe_subnets()
    subnet_data = [{
        'Subnet ID': subnet['SubnetId'],
        'VPC ID': subnet['VpcId'],
        'CIDR Block': subnet['CidrBlock'],
        'Availability Zone': subnet['AvailabilityZone'],
    } for subnet in subnets['Subnets']]
    return pd.DataFrame(subnet_data)

# Function to fetch Security Groups
def get_security_groups():
    groups = ec2_client.describe_security_groups()
    group_data = [{
        'Group Name': group['GroupName'],
        'Group ID': group['GroupId'],
        'Description': group['Description'],
        'VPC ID': group.get('VpcId', 'N/A')
    } for group in groups['SecurityGroups']]
    return pd.DataFrame(group_data)

# Function to fetch DynamoDB Tables
def get_dynamodb_tables():
    tables = dynamodb.list_tables()['TableNames']
    table_data = [{'Table Name': name} for name in tables]
    return pd.DataFrame(table_data)

# Function to fetch NACLs
def get_nacls():
    nacls = ec2_client.describe_network_acls()
    nacl_data = [{
        'NACL ID': nacl['NetworkAclId'],
        'VPC ID': nacl['VpcId'],
        'Is Default': nacl['IsDefault']
    } for nacl in nacls['NetworkAcls']]
    return pd.DataFrame(nacl_data)

# Function to auto-size Excel columns
def auto_adjust_columns(worksheet):
    for column_cells in worksheet.columns:
        length = max(len(str(cell.value)) for cell in column_cells)
        worksheet.column_dimensions[get_column_letter(column_cells[0].column)].width = length

dir_path = 'aws-inventory'

    
# Use the 'with' statement to manage the Excel writer
with pd.ExcelWriter(f'{dir_path}/AWS_Resources.xlsx', engine='openpyxl') as writer:
    get_ec2_instances().to_excel(writer, sheet_name='EC2 Instances', index=False)
    get_rds_instances().to_excel(writer, sheet_name='RDS Instances', index=False)
    get_subnets().to_excel(writer, sheet_name='Subnets', index=False)
    get_security_groups().to_excel(writer, sheet_name='Security Groups', index=False)
    get_dynamodb_tables().to_excel(writer, sheet_name='DynamoDB Tables', index=False)
    get_nacls().to_excel(writer, sheet_name='NACLs', index=False)
    get_nacl_rules().to_excel(writer, sheet_name='NACL Rules', index=False)
    get_route_tables().to_excel(writer, sheet_name='Route Tables', index=False)
    get_security_group_rules().to_excel(writer, sheet_name='Security Group Rules', index=False)   
    get_iam_roles().to_excel(writer, sheet_name='IAM Roles', index=False)
    glue_jobs_df = pd.DataFrame(get_glue_jobs())
    glue_jobs_df.to_excel(writer, sheet_name='Glue Jobs', index=False)
    for sheetname in writer.sheets:
        auto_adjust_columns(writer.sheets[sheetname])