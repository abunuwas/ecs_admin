import datetime

import boto3

from botocore.exceptions import ClientError

from exceptions import EntityExistsError

from core_utils import filter_args

class IAM:
	"""
`	"""

	def __init__(self, aws_parameters=None):
		self.aws_parameters = aws_parameters
		self._make_clients()

	def _make_clients(self):
		if self.aws_parameters is not None:
			self.iam_client = boto3.client('iam', **self.aws_parameters)
		else:
			try:
				self.iam_client = boto3.client('iam')
			except Exception as e:
				print(str(e))
		return None 	

	iam_client = boto3.client('iam')
	iam_resource = boto3.resource('iam')

	def _get_policy_arn_from_create_request(self, request):
		return request['Policy']['Arn']

	def _get_policy_arn(self, policy_name):
		policy = self.list_policies([policy_name])
		return list(policy)[0]['Arn']

	def create_policy(self, **kwargs):
		try:
			request = self._create_policy(**kwargs)
			policy_arn = self._get_policy_arn_from_create_request(request)
		except EntityExistsError:
			policy_arn = self._get_policy_arn(kwargs['policy_name'])
		return policy_arn

	def _create_policy(self, policy_name=None, path=None, policy_document=None, description=None):
		try:
			request = self.iam_client.create_policy(PolicyName=policy_name,
												PolicyDocument=policy_document
												)
			return request
		except ClientError as e:
			if e.response['Error']['Code'] == 'EntityAlreadyExists':
				raise EntityExists		
		return policy

	auto_scaling_group = ''

	def _get_role_arn_from_create_request(self, request):
		return request['Role']['Arn']

	def _get_role_arn(self, role_name):
		arn = self.iam_client.get_role(RoleName=role_name)
		return arn['Role']['Arn']

	def create_role(self, **kwargs):
		try:
			request = self._create_role(**kwargs)
			role_arn = self._get_role_arn_from_create_request(request)
		except EntityExists:
			role_arn = self._get_role_arn(kwargs['role_name'])
		return role_arn

	def _create_role(self, path=None, role_name=None, policy_trust=None):
		'''
		:policy is a trust policy to be passed as an argument
		for the AssumeRolePolicyDocument variable in the 
		createRole API call of IAM. 
		'''
		try:
			request = self.iam_client.create_role(
				#Path='/xmpp_component_role/',
				RoleName=role_name,
				AssumeRolePolicyDocument=policy_trust
				)
			return request
		except ClientError as e:
			if e.response['Error']['Code'] == 'EntityAlreadyExists':
				raise EntityExists

	def _apply_filter(self, filter_params, target):
	    return all(param in target for param in filter_params)

	def list_roles(self, filter_params=None):
		if filter_params is None:
			roles = self._list_all_roles()
		else:
			roles = filter(lambda role: self._apply_filter(filter_params, role['RoleName']), self.list_roles())
		return roles

	def _list_all_roles(self):
		roles = self.iam_client.list_roles()['Roles']
		return roles

	def attach_policy(self, role_name, policy_arn):
		response = self.iam_client.attach_role_policy(RoleName=role_name,
								PolicyArn=policy_arn)
		return response

	def list_policies(self, filter_params=None):
		if filter_params is None:
			policies = self._list_all_policies()
		else:
			policies = filter(lambda policy: self._apply_filter(filter_params, policy['PolicyName']), self._list_all_policies())
		return policies

	def _list_all_policies(self):
		policies = self.iam_client.list_policies()
		return policies['Policies']	

	def get_role_attached_policies(self, role_name):
		policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
		return policies['AttachedPolicies']

	def describe_policy(self, policy_arn):
		description = self.iam_client.get_policy(PolicyArn=policy_arn)
		return description['Policy']

	def get_policy_document(self, policy_arn, version):
		policy_document = self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version)
		return policy_document['PolicyVersion']['Document']

	def document_has_permission(self, document, permission):
		statements = document['Statement']
		return any(permission in statement['Action'] for statement in statements)

	def documents_have_permission(self, documents, permission):
		return any(self.document_has_permission(document, permission) for document in documents)

	def role_has_permissions(self, role_name, permissions):
		'''
		:type permissions: list(string)
		:param permissions: list of permissions that need to be
			checked for a given role. Each of the permissions
			must be a string following AWS permissions notation,
			e.g. 'ecs:DescribeServices'.
		'''
		policies  = self.get_role_attached_policies(role_name)
		policies_descriptions = [self.describe_policy(policy['PolicyArn']) for policy in policies]
		policies_documents = [self.get_policy_document(policy['Arn'], policy['DefaultVersionId']) for policy in policies_descriptions]
		return all(self.documents_have_permission(policies_documents, permission) for permission in permissions)

	def roles_have_permissions(self, roles, permissions):
		return filter(self.role_has_permissions(role, permissions) for role in roles)


#iam = IAM()

#roles = iam.list_roles(['xmpp']) # -> ['xmpp_component_task', 'xmpp_component_task_role']
#for role in roles:
#    print(role['RoleName'])

#request = {'Role': {'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Sid': ''}]}, 'RoleName': 'lambda_ecs_role_test', 'CreateDate': datetime.datetime(2016, 9, 6, 9, 0, 48, 309000), 'Arn': 'arn:aws:iam::876701361933:role/lambda_ecs_role_test', 'Path': '/', 'RoleId': 'AROAJHW24XF6JJBQA6WPQ'}, 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': '674c4859-7410-11e6-bf4f-7b2766e599ec'}}
#arn = iam._get_role_arn_from_create_request(request)
#print(arn) -> arn:aws:iam::876701361933:role/lambda_ecs_role_test

#roles = iam.list_roles()
#for role in roles:
#	print(role['RoleName'], role['Arn'], role['AssumeRolePolicyDocument'])
# FOR TEST:
#roles_names = [role['RoleName'] for role in roles]
#assert('aws-elasticbeanstalk-ec2-role' in roles_names)

#policies = iam.list_policies(['ecs'])
#for policy in policies:
#	print(policy['PolicyName'])
# -> ['ecs_role_policy', 'lambda_ecs', 'lambda_ecs_test']

#document = {'Statement': [{'Action': ['logs:*'], 'Effect': 'Allow', 'Resource': 'arn:aws:logs:*:*:*'}, {'Action': ['ecs:DescribeServices', 'ecs:UpdateService'], 'Effect': 'Allow', 'Resource': ['*']}], 'Version': '2012-10-17'}
#permission = 'ecs:DescribeServices'

#print(iam.document_has_permission(document, permission)) #-> True

#policy_arn = iam._get_policy_arn(policy_name='ecs_role_policy')
#print(policy_arn) # -> arn:aws:iam::876701361933:policy/ecs_role_policy

#description = iam.describe_policy(policy_arn)
#print(description) 
# -> {'Path': '/', 'IsAttachable': True, 'PolicyId': 'ANPAISXPETQJJTKSCHHDK', 'CreateDate': datetime.datetime(2016, 8, 25, 12, 14, 27, tzinfo=tzutc()), 'PolicyName': 'ecs_role_policy', 'AttachmentCount': 1, 'DefaultVersionId': 'v2', 'UpdateDate': datetime.datetime(2016, 8, 30, 11, 1, 27, tzinfo=tzutc()), 'Arn': 'arn:aws:iam::876701361933:policy/ecs_role_policy'}

#version = description['DefaultVersionId']

#policy_document = iam.get_policy_document(policy_arn, version)
#print(policy_document)
# -> {'Version': '2012-10-17', 'Statement': [{'Action': ['ecs:CreateCluster', 'ecs:DeregisterContainerInstance', 'ecs:DiscoverPollEndpoint', 'ecs:Poll', 'ecs:RegisterContainerInstance', 'ecs:StartTelemetrySession', 'ecs:Submit*', 'ecr:GetAuthorizationToken', 'ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage', 'logs:CreateLogStream', 'logs:PutLogEvents', 's3:GetObject'], 'Resource': '*', 'Effect': 'Allow'}]}

#doc_statements = document['Statement']

#for statement in doc_statements:
#	print(statement['Action'])
# ->
# ['logs:*']
# ['ecs:DescribeServices', 'ecs:UpdateService']

#documents = iam.role_has_permissions('lambda_ecs_role', ['ecs:DescribeServices', 'ecs:UpdateService'])
#print(documents) #-> True

