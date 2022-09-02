import boto3

SECURITY_GROUP_IDS = {
    "sg-example": "2022-09-02UTC13:26:19",
}
AUTHORIZE_INGRESS_DRY_RUN = True

def read_report(file_path):
    """
    Reads the report and return a list[dict] data.

    :param file_path: Name of the report file to read from.
    :return: The security group rules written at the report file.
    """
    with open(file_path, 'r') as file_: data_lake = file_.readlines()
    rules = []
    for data in data_lake[1:]: # Ignore header/first line
        # Remove unnecessary characters and
        # split lines with commas to generate a list with each key
        data = data.replace('\n', '').split(',')
        rules.append({
            "ip_protocol": data[0],
            "from_port": data[1],
            "to_port": data[2],
            "from_source": data[3],
            "description": data[4]
        })
    
    return rules

def authorize_ingress(sg_id, rules):
    """
    Authorizes ingress rules.

    :param sg_id: Target security group ID.
    :param rules: Rules to authorize.
    """
    ec2_resource = boto3.resource('ec2', 'sa-east-1')
    security_group = ec2_resource.SecurityGroup(sg_id)
    for rule in rules:
        try:
            # If the source of the rule is another security group
            if rule["from_source"].startswith("sg-"):
                source_security_group = ec2_resource.SecurityGroup(rule["from_source"])
                security_group.authorize_ingress(
                  IpProtocol=rule["ip_protocol"],
                  FromPort=rule["from_port"],
                  ToPort=rule["to_port"],
                  SourceSecurityGroupName=source_security_group.group_name,
                  Description=rule["description"],
                  DryRun=AUTHORIZE_INGRESS_DRY_RUN
                )
            # If the source of the rule is an IP block
            else:
                security_group.authorize_ingress(
                  IpProtocol=rule["ip_protocol"],
                  FromPort=rule["from_port"],
                  ToPort=rule["to_port"],
                  CidrIp=rule["from_source"],
                  Description=rule["description"],
                  DryRun=AUTHORIZE_INGRESS_DRY_RUN
                )
        except Exception as e: 
            print(e)

for security_group_id in SECURITY_GROUP_IDS:
    file_datetime = SECURITY_GROUP_IDS[security_group_id]
    file_path = f"output/{security_group_id}/{file_datetime}-{security_group_id}-deleted"
    authorize_ingress(security_group_id, read_report(file_path))