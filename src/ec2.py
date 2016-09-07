import boto3

from botocore.exceptions import ClientError

from exceptions import EntityExists, LimitExceeded
from core_utils import filter_args



iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')

def _create_key_pair(key_name):
	try: 
		key_pair = ec2_client.create_key_pair(KeyName=key_name)
		return key_pair
	except ClientError as e:
		if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
			raise EntityExists


def create_security_group(name, description, dry_run=False):
	api_args = {
				'DryRun': dry_run,
				'GroupName': name,
				'Description': description
	}
	try:
		group = ec2_client.create_security_group(**api_args)
	except ClientError as e:
		if e['Error']['Code'] == 'InvalidGroup.Duplicate':
			raise EntityExists
	return group

def add_group_rule(group, dry_run=False, **kwargs):
	api_args = {
				'DryRun': dry_run,
				'GroupName': group,
	}
	api_args.update(kwargs)
	args = filter_args(api_args)
	response = ec2_client.authorize_security_group_ingress(**args)
	return response

def create_instance_profile(name=None, path=None):
	try:
		profile = iam_client.create_instance_profile(InstanceProfileName=name)
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			raise EntityExists
	return profile

'''
def create_instance_profile(**kwargs):
	# A wrapper method for a _create_instance_profile might be good
	# if EntityExists can be modified in that case to throw an error
	# with the arn of the existing profile as msg. In that case,
	# client code can catch the error and decide that returning
	# the existing arn might just be ok. 
	try:
		profile = _create_instance_profile(**kwargs)
	except EntityExists:
		profile = None
	return profile
'''

def list_instance_profiles(**kwargs):
	args = filter_args(kwargs)
	profiles = iam_client.list_instance_profiles(**args)
	return profiles['InstanceProfiles']

def update_instance_profile():
	pass

def _add_role2profile(role_name=None, profile_name=None):
	try:
		response = iam_client.add_role_to_instance_profile(InstanceProfileName=profile_name,
														RoleName=role_name)
		return response
	except ClientError as e:
		if e.response['Error']['Code'] == 'LimitExceeded':
			raise LimitExceeded

def add_role2profile(**kwargs):
	try:
		response = _add_role2profile(**kwargs)
	except LimitExceeded:
		# Raise a proper error 
		print('Instance profile already has an IAM role.')
		response = None
	return response 

def get_user_data(file):
	return open(file).read()

def find_images():
	images = ec2_client.describe_images(Filters=[
											{
												'Name': 'architecture', 
												'Values': ['x86_64']
											},
											{
												'Name': 'owner-id',
												'Values': ['591542846629']
											},
											{
												'Name': 'virtualization-type',
												'Values': ['hvm']
											},
											{
												'Name': 'root-device-type',
												'Values': ['ebs']
											}
										])
	return images

def iso2map(iso):
	'''
	Parses a date in ISO format, e.g. 2015-10-28T21:08:08.000Z,
	and returns a map object with year, month converted into int
	types. The return values must be unpacked. 
	'''
	year_month_day_str_list = iso[:10].split('-')
	return map(int, year_month_day_str_list)

def get_dt(image):
	if 'preview' not in image['Name']:
		date = image['CreationDate']
		year, month, day = iso2map(date)
		dt = datetime.datetime(year, month, day)
		return dt

def get_most_recent_opt_AMI():
	images = (image for image in find_images()['Images'] if 'preview' not in image['Name'])
	maxim = max(images, key=lambda x: get_dt(x))
	return maxim

def launch_ec2(key_name, 
				security_groups, 
				profile_arn,
				user_data=None, 
				dry_run=False,
				image_id=None, 
				min_count=1, 
				max_count=1, 
				instance_type='t2.micro', 
				monitoring=True, 
				**kwargs
				):
	if image_id is None:
		image_id = get_most_recent_opt_AMI()['ImageId']
	api_args = {
				'DryRun': dry_run,
				'ImageId': image_id,
				'MinCount': min_count,
				'MaxCount': max_count,
				'KeyName': key_name,
				#'SecurityGroups'=[], This is for VPCs
				'SecurityGroupIds': security_goups,
				'UserData': user_data,
				'InstanceType': instance_type,
				#'Placement'={
					#'AvailabilityZone': 'eu-west-1',
					#'GroupName': 'xmpp_component_cluster',
					#'Tenancy': ,
					#'HostId': ,
					#'Affinity': 
				#},
				'Monitoring'={
					'Enabled': monitoring
				},
				#'SubnetId'=
				#'DisableApiTerminator'
				#'InstanceInitiatedShutdownBehavior'
				#'PrivateIpAddress'
				#'ClientTocken'
				#'NetworkInterfaces'
				'IamInstanceProfile'={
					'Arn': 'arn:aws:iam::876701361933:instance-profile/ec2InstanceProfileECS'
					#'Name': 'XMPP-instance-profile'
				},
				#EbsOptimized
	}
	api_args.update(kwargs)
	args = filter_args(api_args)
	instance = ec2_client.run_instances(args)
	return instance

def list_ec2():
	ec2s = ec2_resource.instances.all()
	return ec2s

def describe_ec2(ec2):
	description = ec2_client.describe_instances(InstanceIds=ec2)
	return description['Reservations']

def stop_instances(instances):
	respnse = ec2_client.stop_instances(InstanceIds=instances)
	return response 

def terminate_instances(instances):
	response = ec2_client.terminate_instances(InstanceIds=instances)
	return response 



#key = create_key_pair('xmpp')
#print(key)

#group = create_security_group('a_group', 'a_group')
#print(group) 

#profiles = list_instance_profiles()
#print(profiles)

#ec2s = list_ec2()
#for ec2 in ec2s:
#	description = describe_ec2([ec2._id])[0]
#	print(description.keys())
