import boto3

from botocore.exceptions import ClientError

from exceptions import EntityExistsError, LimitExceededError, DoesNotExistError, MissingValueError
from core_utils import filter_args


class EC2Client:
	def __init__(self, aws_parameters=None):
		self.aws_parameters = aws_parameters
		self._make_clients()
		self._missing_value_msg = 'Please make sure you have set a value for {value}.'

	def _make_clients(self):
		if self.aws_parameters is not None:
			self.iam_client = boto3.client('iam', **self.aws_parameters)
			self.ec2_client = boto3.client('ec2', **self.aws_parameters)
			self.ec2_resource = boto3.resource('ec2', **self.aws_parameters)
		else:
			try:
				self.iam_client = boto3.client('iam')
				self.ec2_client = boto3.client('ec2')
				self.ec2_resource = boto3.resource('ec2')
			except Exception as e:
				print(str(e))
		return None 

	def _create_key_pair(self, **kwargs):
		try: 
			return self.ec2_client.create_key_pair(KeyName=kwargs['key_name'])
		except ClientError as e:
			if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
				raise EntityExistsError('A key pair already exists with name: {}.'.format(kwargs['key_name']))

	def create_key_pair(self, key_name, output=None, **kwargs):
		key = self._create_key_pair(key_name=key_name, **kwargs)
		if output is None:
			return key['KeyMaterial']
		else:
			with open(output) as file:
				## Handle possible file errors
				## chmod 400
				file.write(self.key_pair['KeyMaterial'])
			return None		

	def _create_security_group(self, name, description, dry_run=False, **kwargs):
		api_args = {
					'DryRun': dry_run,
					'GroupName': name,
					'Description': description
					}
		api_args.update(kwargs)
		args = filter_args(api_args)
		try:
			security_group = self.ec2_client.create_security_group(**args)
		except ClientError as e:
			if e['Error']['Code'] == 'InvalidGroup.Duplicate':
				msg = 'A security group already exists with name: {}.'.format(name)
				raise EntityExistsError(msg)
		return security_group

	def create_security_group(self, name, description, dry_run=False, **kwargs):
		return self._create_security_group(name=name, description=description, dry_run=dry_run, **kwargs)

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
			profile = self.iam_client.create_instance_profile(**args)
		except ClientError as e:
			if e.response['Error']['Code'] == 'EntityAlreadyExists':
				msg = 'A profile instance already exists with name: {}'.format(name)
				raise EntityExistsError(msg)
			else:
				print(str(e))
		return profile

	def create_instance_profile(self, **kwargs):
		return self._create_instance_profile(**kwargs)['InstanceProfile']['Arn']

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
				msg = '''
					  Instance profile {} already has a role. You cannot attach more 
					  than one role to an instance profile.
					  '''.format(profile_name)
				raise EntityExistsError(msg)

	def add_role2profile(self, role_name, profile_name):
		return self._add_role2profile(role_name=role_name, profile_name=profile_name)

	def get_user_data(self, file):
		with open(file) as file:
			data = file.read()
			return data

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
		images = self.ec2_client.describe_images(**args)
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
						'Arn': profile_arn
						#'Name': 'XMPP-instance-profile'
					},
					#EbsOptimized
		}
		api_args.update(kwargs)
		args = filter_args(api_args)
		instance = self.ec2_client.run_instances(**args)
		return instance

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

	def stop_instances(self, instances):
		response = self.ec2_client.stop_instances(InstanceIds=instances)
		return response 

	def terminate_instances(self, instances):
		response = self.ec2_client.terminate_instances(InstanceIds=instances)
		return response 


class EC2Instance(EC2Client):
	def __init__(self, 
				 security_group, 
				 key_name, 
				 profile_name, 
				 profile_path=None,
				 profile_role=None,
				 vpn=None, 
				 aws_parameters=None, 
				 security_group_description=None, 
				 key_output=None,
				 user_data_file=None
				 ):
		EC2Client.__init__(self, aws_parameters=aws_parameters)
		self._make_clients() 

		self.security_group = security_group
		self.security_group_description = security_group_description

		self.key_name = key_name
		self.key_output = key_output

		self.vpn = vpn

		self.profile_name = profile_name
		self.profile_path = profile_path
		self.profile_role = profile_role

		self.user_data_file = user_data_file

		self._missing_value_msg = 'Please make sure you have set a value for {value}.'

	def _make_clients(self):
		self.iam_client = boto3.client('iam')
		self.ec2_client = boto3.client('ec2')
		self.ec2_resource = boto3.resource('ec2')

	def get_ready(self):
		# Make sure you provie a key_output value
		# Make sure you create a profile_role with
		# the IAM client. 
		self.get_security_group()
		self.get_key_pair()
		self.profile_arn = self.get_instance_profile()
		self.add_role2profile(self.profile_role, self.profile_name)
		self.user_data_file = get_user_data()
		self.launch()


	def get_key_pair(self, **kwargs):
		if self.key_name is None:
			msg = self._missing_value_msg.format(value='self.key_name')
			raise MissingValueError(msg)
		try:
			key = self.create_key_pair(self.key_name, self.key_output)
		except EntityExistsError:
			# Key already exists, so nothing has to be done. Object's
			# key_name attribute can be kept as it is. 
			pass
		return self.key_name

	def get_security_group(self, dry_run=False, **kwargs):
		if self.security_group is None:
			msg = self._missing_value_msg.format(value='self.security_group')
			raise MissingValueError(msg)
		try:
			## This assignment might be wrong. Test by launching an instance with a new security group. 
			## If it raises an error, it means what we need is the group name, not the group id as returned
			## by the API call. 
			if self.security_group_description is None:
				msg = self._missing_value_msg.format(value='self.security_group_description')
				raise MissingValueError(msg)
			group = self.list_security_groups([self.security_group])
		except DoesNotExistError:
			self.create_security_group(name=self.security_group, description=self.security_group_description, dry_run=dry_run, **kwargs)
		return self.security_group

	def _list_security_groups(self, names, **kwargs):
		api_args = { 'GroupNames': names }
		api_args.update(kwargs)
		args = filter_args(api_args)
		try:
			groups = self.ec2_client.describe_security_groups(**args)
		except ClientError as e:
			if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
				msg = 'The following security groups do not exist: {}'.format(', '.join(names))
				raise DoesNotExistError(msg)
		return groups

	def list_security_groups(self, names, **kwargs):
		return self._list_security_groups(names, **kwargs)['SecurityGroups']

	def _get_instance_profile(self, **kwargs):
		api_args = { 'InstanceProfileName': kwargs['name'], 'Path': kwargs['path'] }
		args = filter_args(api_args)
		try: 
			profile = self.iam_client.get_instance_profile(**args)
		except ClientError as e:
			if e.response['Error']['Code'] == 'NoSuchEntity':
				msg = 'No profile instance could be found with name: {}'.format(kwargs['name'])
				raise DoesNotExistError(msg)
		return profile

	def get_instance_profile(self, **kwargs):		
		if self.profile_name is None:
			msg = self._missing_value_msg.format(value='self.profile_name')
			raise MissingValueError(msg)
		try:
			self.profile_arn = self.create_instance_profile(name=self.profile_name, path=self.profile_path, **kwargs)
		except EntityExistsError:
			self.profile_arn = self._get_instance_profile(name=self.profile_name, path=self.profile_path)['InstanceProfile']['Arn'] 
		return self.profile_arn 

	def _launch(self, key_name, security_group, profile, **kwargs):
		'''
		Low level method which returns all the metadata coming with the response to the AWS API call 
		ec2_client.call to run_instances. To set the class instance attribute self.instance_id at 
		launch time, call the equivalent high level method, self.launch_ec2. 
		'''
		missing_params = list(filter(lambda param: param is None, [key_name, security_group, profile]))
		if len(missing_params) > 0:
			msg = 'The following values need to be set: {}'.format(', '.join(missing_params.split()))
			raise MissingValueError(msg)
		instance = launch_ec2s(self, key_name=key_name, security_goup=security_goup, profile=profile, **kwargs)
		return instance

	def launch(self, **kwargs):
		instance = _launch(self, key_name=self.key_name, security_group=self.security_group, profile=self.profile_arn, **kwargs)
		self.instance_id = instance['Instances'][0]['InstanceId']
		return self.instance_id

	def describe(self):
		if not hasattr(instance_id):
			raise Exception('Please launch an EC2 instance before attempting to describe.')
		return self.describe_ec2s(ec2=self.instance_id)

	def stop(self):
		return self.stop_instances(self.instance_id)

	def terminate(self):
		return self.terminate_instances(self.instance_id)


#ec2 = EC2Instance() -> TypeError: __init__() missing 3 required positional arguments: 'security_group', 'key_name', and 'profile_name'
#ec2 = EC2Instance('sgxmpp', 'keyxmpp', 'profilexmpp')
#ec2.security_group_description = 'a description'
#ec2.get_ready() # At this point only profile_role is missing -> Invalid type for parameter RoleName, value: None, type: <class 'NoneType'>, valid types: <class 'str'>
#profile = ec2.create_instance_profile(name='xmpp22')
#print(profile) -> if exists, None.
#user_data = ec2.get_user_data('docker-login.txt')
#print(user_data) -> prints the file correctly

#profile = ec2.get_instance_profile(name='mueje', path='/marara/')
#print(profile)
#print(ec2.profile)
#instance = ec2.launch_ec2()
#print(instance)

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
