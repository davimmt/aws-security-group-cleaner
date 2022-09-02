import boto3
import datetime
from IPy import IP
from pathlib import Path
import os

SECURITY_GROUP_IDS = [
    "sg-example",
]
NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dUTC%H:%M:%S")
REVOKE_INGRESS_DRY_RUN = True
PUBLIC_PORTS = (80, 443)
IGNORE_IP_BLOCKS = ('54.38.', '52.23.33.33/32')

def read_security_group_rules(sg_id):
    """
    Reads the security group rules and return a list[dict] data.

    :param sg_id: Target security group ID.
    :return: The security group rules.
    """
    rules = []
    ec2_client = boto3.client('ec2', 'sa-east-1')
    for rule in ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]['IpPermissions']:
        # Clean up variables each iteration
        description = ""
        from_port = ""
        to_port = ""
        ip_protocol = rule['IpProtocol']

        # If 'All traffic'
        if ip_protocol != "-1":
            from_port = rule['FromPort']
            to_port = rule['ToPort']

        # If source is an IPv4
        if len(rule['IpRanges']) > 0:
            for ip_range in rule['IpRanges']:
                try: description = ip_range['Description']
                except: pass
                cidr_block = ip_range['CidrIp']
                rules.append({
                    "ip_protocol": ip_protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "from_source": cidr_block,
                    "description": description
                })

        # If source is an IPv6
        if len(rule['Ipv6Ranges']) > 0:
            for ip_range in rule['Ipv6Ranges']:
                try: description = ip_range['Description']
                except: pass
                cidr_block = ip_range['CidrIpv6']
                rules.append({
                    "ip_protocol": ip_protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "from_source": cidr_block,
                    "description": description
                })

        # If source is another security group
        if len(rule['UserIdGroupPairs']) > 0:
            for source in rule['UserIdGroupPairs']:
                from_source = source['GroupId']
                try: description = ip_range['Description']
                except: pass
                rules.append({
                    "ip_protocol": ip_protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "from_source": from_source,
                    "description": description
                })
        
    return rules

def write_report(file_path, rules):
    """
    Reads the security group rules and return a list[dict] data.

    :param file_path: Name of the report file to write in.
    :param rules: Rules to write in the report file.
    :return: Name of the report file path.
    """
    # Check if directory exists and, if it doesn't, create
    Path(os.path.dirname(file_path)).mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w+') as file:
        file.write("ip_protocol,from_port,to_port,from_source,description\n")
        for rule in rules:
            file.write("%s,%s,%s,%s,%s\n" % (
                rule["ip_protocol"],
                rule["from_port"],
                rule["to_port"],
                rule["from_source"],
                rule["description"]
            ))

    return file_path

def revoke_ingress(sg_id, rules):
    """
    Revokes ingress rules.

    :param sg_id: Target security group ID.
    :param rules: Rules to revoke.
    :return: The security group that were revoked.
    """
    deleted_rules = []
    for rule in rules:
        # Do not delete rule if:
        # - source is another security_group
        # - source starts with any string from IGNORE_IP_BLOCKS
        # - ports belong to PUBLIC_PORTS range
        # - source is from a private CIDR range
        if rule["from_source"].startswith("sg-") or \
           rule["from_source"].startswith(IGNORE_IP_BLOCKS) or \
           rule["from_port"] in PUBLIC_PORTS or \
           (IP(rule["from_source"]).iptype() == 'PRIVATE' and rule["from_source"] != '0.0.0.0/0'):
            continue

        deleted_rules.append({
            "ip_protocol": rule["ip_protocol"],
            "from_port": rule["from_port"],
            "to_port": rule["to_port"],
            "from_source": rule["from_source"],
            "description": rule["description"]
        })
        try: boto3.resource('ec2', 'sa-east-1').SecurityGroup(sg_id).revoke_ingress(
            CidrIp=rule["from_source"],
            FromPort=rule["from_port"],
            ToPort=rule["to_port"],
            IpProtocol=rule["ip_protocol"], 
            DryRun=REVOKE_INGRESS_DRY_RUN
        )
        except Exception as e: 
            print(e)
    
    return deleted_rules

for security_group_id in SECURITY_GROUP_IDS:
    output_file_path = f"output/{security_group_id}/{NOW}-{security_group_id}"
    rules = read_security_group_rules(security_group_id)
    write_report(output_file_path, rules)
    deleted_rules = revoke_ingress(security_group_id, rules)
    write_report(f"{output_file_path}-deleted", deleted_rules)