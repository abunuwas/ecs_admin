import boto3

from botocore.exceptions import ClientError

from exceptions import EntityExists, LimitExceeded, DoesNotExist
from core_utils import filter_args


class EC2:
	def __init__(self, security_group=None, instance_type=None, image_id=None, key_name=None, vpn=None, profile=None, aws_parameters=None):
		self.security_group = security_group
		self.instance_type = instance_type
		self.image_id = image_id
		self.key_name = key_name
		self.vpn = vpn
		self.profile = profile
		self.instance_id = None
		self.aws_parameters = aws_parameters
		self._make_clients()

	def _make_clients(self):
		if self.aws_parameters is not None:
			self.iam_client = boto3.client('iam', **aws_parameters)
			self.ec2_client = boto3.client('ec2', **aws_parameters)
			self.ec2_resource = boto3.resource('ec2', **aws_parameters)
		else:
			try:
				self.iam_client = boto3.client('iam')
				self.ec2_client = boto3.client('ec2')
				self.ec2_resource = boto3.resource('ec2')
			except Exception as e:
				print(str(e))
		return None 

	def create_key_pair(self, key_name, output=None):
		try: 
			self.key_pair = ec2_client.create_key_pair(KeyName=key_name)
			if output is None:
				return self.key_pair['KeyMaterial']
			else:
				with open(output) as file:
					## Handle possible file errors
					## chmod 400
					file.write(self.key_pair['KeyMaterial'])
				return None
		except ClientError as e:
			if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
				raise EntityExists

	def create_security_group(self, name, description, dry_run=False):
		api_args = {
					'DryRun': dry_run,
					'GroupName': name,
					'Description': description
					}
		try:
			self.security_group = self.ec2_client.create_security_group(**api_args)
		except ClientError as e:
			if e['Error']['Code'] == 'InvalidGroup.Duplicate':
				raise EntityExists
		return self.security_group

	def add_group_rule(self, group, dry_run=False, **kwargs):
		api_args = {
					'DryRun': dry_run,
					'GroupName': group,
		}
		api_args.update(kwargs)
		args = filter_args(api_args)
		response = ec2_client.authorize_security_group_ingress(**args)
		return response

	def _create_instance_profile(self, name, path=None):
		api_args = { 'InstanceProfileName': name, 'Path': path }
		args = filter_args(api_args)
		try:
			self.profile = self.iam_client.create_instance_profile(**args)
		except ClientError as e:
			if e.response['Error']['Code'] == 'EntityAlreadyExists':
				raise EntityExists
			else:
				print(str(e))
		return self.profile['InstanceProfile']['Arn']

	def create_instance_profile(self, **kwargs):
		try:
			self.profile = self._create_instance_profile(**kwargs)
			return self.profile
		except EntityExists:
			'''
			If the instance profile already exists, return None.
			'''
			## Change print() for log()
			print('Profile already exists.')

	def _get_instance_profile(self, name):
		try: 
			self.profile = self.iam_client.get_instance_profile(InstanceProfileName=name)
		except ClientError as e:
			if e.response['Error']['Code'] == 'NoSuchEntity':
				raise DoesNotExist
		return self.profile['InstanceProfile']['Arn']

	def get_instance_profile(self, **kwargs):
		try:
			self.profile = self._create_instance_profile(**kwargs)
		except EntityExists:
			self.profile = self._get_instance_profile(kwargs['name']) 
		return self.profile 

	def list_instance_profiles(self, **kwargs):
		args = filter_args(kwargs)
		profiles = self.iam_client.list_instance_profiles(**args)
		return profiles['InstanceProfiles']

	def update_instance_profile():
		pass

	def _add_role2profile(self, role_name=None, profile_name=None):
		try:
			response = self.iam_client.add_role_to_instance_profile(InstanceProfileName=profile_name,
															RoleName=role_name)
			return response
		except ClientError as e:
			if e.response['Error']['Code'] == 'LimitExceeded':
				raise LimitExceeded

	def add_role2profile(self, **kwargs):
		try:
			response = self._add_role2profile(**kwargs)
		except LimitExceeded:
			# Raise a proper error 
			print('Instance profile already has an IAM role.')
			response = None
		return response 

	def get_user_data(self, file):
		return open(file).read()

	def find_images(self, filters=None, **kwargs):
		if filters is None:
			filters = [
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
			]
		api_args = { 'Filters': filteres }
		api_args.update(kwargs)
		args = filter_args(api_args)
		images = self.ec2_client.describe_images(args)
		return images

	def _iso2map(self, iso):
		'''
		Parses a date in ISO format, e.g. 2015-10-28T21:08:08.000Z,
		and returns a map object with year, month converted into int
		types. The return values must be unpacked. 
		'''
		year_month_day_str_list = iso[:10].split('-')
		return map(int, year_month_day_str_list)

	def _get_dt(self, image):
		if 'preview' not in image['Name']:
			date = image['CreationDate']
			year, month, day = iso2map(date)
			dt = datetime.datetime(year, month, day)
			return dt

	def get_most_recent_opt_AMI(self):
		images = (image for image in find_images()['Images'] if 'preview' not in image['Name'])
		maxim = max(images, key=lambda x: get_dt(x))
		return maxim

	def launch_ec2s(self, 
					key_name, 
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
					'Monitoring': {
						'Enabled': monitoring
					},
					#'SubnetId'=
					#'DisableApiTerminator'
					#'InstanceInitiatedShutdownBehavior'
					#'PrivateIpAddress'
					#'ClientTocken'
					#'NetworkInterfaces'
					'IamInstanceProfile': {
						'Arn': 'arn:aws:iam::876701361933:instance-profile/ec2InstanceProfileECS'
						#'Name': 'XMPP-instance-profile'
					},
					#EbsOptimized
		}
		api_args.update(kwargs)
		args = filter_args(api_args)
		instance = self.ec2_client.run_instances(args)
		return instance

	def launch_ec2(self, **kwargs):
		params = { 'key_name': self.key_name, 'security_group': self.security_group, 'profile': self.profile }
		if all(param is not None for param in params.values()):
			instance = self.launch_ec2s(key_name=self.key_name, security_goups=self.security_groups, profile_arn=self.profile)
			self.instance_id = instance['Instances']['InstanceId']
			return instance 
		else:
			missing_params = filter(lambda param: param[1] is None, params.items())
			print(list(missing_params))
			print('Please make sure you have assigned valid values for the following parameters: {}.'.format(', '.join(list(missing_params))))
			return None 

	def list_ec2(self):
		ec2s = self.ec2_resource.instances.all()
		return ec2s

	def describe_ec2s(self, ec2, **kwargs):
		'''
		:type ec2: list(string)
		:parameter ec2: A list of instance ids. 
		'''
		api_args = { 'InstanceIds': ec2 }
		api_args.update(**kwargs)
		args = filter_args(api_args)
		description = self.ec2_client.describe_instances(args)
		return description['Reservations']

	def describe_ec2(self):
		return self.describe_ec2s(ec2=self.instance_id)

	def stop_instances(self, instances):
		response = self.ec2_client.stop_instances(InstanceIds=instances)
		return response 

	def terminate_instances(self, instances):
		response = self.ec2_client.terminate_instances(InstanceIds=instances)
		return response 

ec2 = EC2()
#profile = ec2.create_instance_profile(name='xmpp22')
#print(profile) -> if exists, None.
#user_data = ec2.get_user_data('docker-login.txt')
#print(user_data) -> prints the file correctly

profile = ec2.get_instance_profile(name='mueje', path='/marara/')
print(profile)
print(ec2.profile)
instance = ec2.launch_ec2()
print(instance)

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
