import boto3
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')

def create_group():
	group = ec2_client.create_security_group(DryRun=True,
											GroupName='ECS_Group',
											Description='Security group for instances running in a cluster.'
											)
	return group

def add_group_rule(group=None):
	response = ec2_client.authorize_security_group_ingress(DryRun=True,
															GroupName='ECS_Group',
															#SourceSecurityGroupName
															#SourceSecurityGroupOwnerId
															#IpProtocol
															#FromPort
															#ToPort
															#CidrIp
															IpPermissions={
																			#'IpProtocol'
																			#FromPort
																			#ToPort
																			#UserIdGroupPairs
															}
															)
	return response

def create_instance_profile(name=None, path=None):
	profile = iam_client.create_instance_profile(InstanceProfileName='ec2InstanceProfileECS')
	return profile

def list_instance_profiles():
	profiles = iam_client.list_instance_profiles()
	return profiles['InstanceProfiles']

def update_instance_profile():
	pass


def add_role2profile(role_name=None, profile_name=None):
	response = iam_client.add_role_to_instance_profile(InstanceProfileName='ec2InstanceProfileECS',
														RoleName='ec2InstanceRole')
	return response

docker_login = open('docker-login.txt').read()

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
	types. The values must be unpacked. 
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

def launch_ec2():
	image_id = get_most_recent_opt_AMI()['ImageId']
	instance = ec2_client.run_instances(#ryRun=True,
				ImageId=image_id,
				MinCount=1,
				MaxCount=1,
				KeyName='ecs_cluster',
				#SecurityGroups=[], This is for VPCs
				SecurityGroupIds=['testxmpp'],
				UserData=docker_login,
				InstanceType='t2.micro',
				#Placement={
					#'AvailabilityZone': 'eu-west-1',
					#'GroupName': 'xmpp_component_cluster',
					#'Tenancy': ,
					#'HostId': ,
					#'Affinity': 
				#},
				#KernelId='',
				#RamdiskId,
				#BlockDeviceMappings=[]
				Monitoring={
					'Enabled': True
				},
				#SubnetId=
				#DisableApiTerminator
				#InstanceInitiatedShutdownBehavior
				#PrivateIpAddress
				#ClientTocken
				#AdditionalInfo
				#NetworkInterfaces
				IamInstanceProfile={
					'Arn': 'arn:aws:iam::876701361933:instance-profile/ec2InstanceProfileECS'
					#'Name': 'XMPP-instance-profile'
				},
				#EbsOptimized
				)
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

#ec2s = list_ec2()
#for ec2 in ec2s:
#	description = describe_ec2([ec2._id])[0]
#	print(description.keys())
