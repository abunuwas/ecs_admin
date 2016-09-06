import datetime

import boto3

from botocore.exceptions import ClientError

from exceptions import EntityExists


iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')

def _get_policy_arn_from_create_request(request):
	return request['Policy']['Arn']

def _get_policy_arn(policy_name):
	policy = list_policies([policy_name])
	return list(policy)[0]['Arn']

def create_policy(**kwargs):
	try:
		request = _create_policy(**kwargs)
		policy_arn = _get_policy_arn_from_create_request(request)
	except EntityExists:
		policy_arn = _get_policy_arn(kwargs['policy_name'])
	return policy_arn

def _create_policy(policy_name=None, path=None, policy_document=None, description=None):
	try:
		request = iam_client.create_policy(PolicyName=policy_name,
											PolicyDocument=policy_document
											)
		return request
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			raise EntityExists		
	return policy

auto_scaling_group = ''

def _get_role_arn_from_create_request(request):
	return request['Role']['Arn']

def _get_role_arn(role_name):
	arn = iam_client.get_role(RoleName=role_name)
	return arn['Role']['Arn']

#request = {'Role': {'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Sid': ''}]}, 'RoleName': 'lambda_ecs_role_test', 'CreateDate': datetime.datetime(2016, 9, 6, 9, 0, 48, 309000), 'Arn': 'arn:aws:iam::876701361933:role/lambda_ecs_role_test', 'Path': '/', 'RoleId': 'AROAJHW24XF6JJBQA6WPQ'}, 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': '674c4859-7410-11e6-bf4f-7b2766e599ec'}}
#arn = _get_role_arn_from_request(request)
#print(arn)

def create_role(**kwargs):
	try:
		request = _create_role(**kwargs)
		role_arn = _get_role_arn_from_create_request(request)
	except EntityExists:
		role_arn = _get_role_arn(kwargs['role_name'])
	return role_arn

def _create_role(path=None, role_name=None, policy_trust=None):
	'''
	:policy is a trust policy to be passed as an argument
	for the AssumeRolePolicyDocument variable in the 
	createRole API call of IAM. 
	'''
	try:
		request = iam_client.create_role(
			#Path='/xmpp_component_role/',
			RoleName=role_name,
			AssumeRolePolicyDocument=policy_trust
			)
		return request
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			raise EntityExists

def apply_filter(filter_params, target):
    return all(param in target for param in filter_params)

def list_roles(filter_params=None):
	if filter_params is None:
		roles = _list_all_roles()
	else:
		roles = filter(lambda role: apply_filter(filter_params, role['RoleName']), list_roles())
	return roles

def _list_all_roles():
	roles = iam_client.list_roles()['Roles']
	return roles

roles = list_roles(['xmpp'])
for role in roles:
    print(role['RoleName'])

#roles = list_roles()
#for role in roles:
#	print(role.keys())
#	print(role['RoleName'], role['Arn'], role['AssumeRolePolicyDocument'])

def attach_policy(role_name=None, policy_arn=None):
	response = iam_client.attach_role_policy(RoleName=role_name,
							PolicyArn=policy_arn)
	return response

def list_policies(filter_params=None):
	if filter_params is None:
		policies = _list_all_policies()
	else:
		policies = filter(lambda policy: apply_filter(filter_params, policy['PolicyName']), _list_all_policies())
	return policies

def _list_all_policies():
	policies = iam_client.list_policies()
	return policies['Policies']	

policies = list_policies(['ecs'])
for policy in policies:
	print(policy['PolicyName'])

def get_role_attached_policies(role_name):
	policies = iam_client.list_attached_role_policies(RoleName=role_name)
	return policies['AttachedPolicies']

def describe_policy(policy_arn):
	description = iam_client.get_policy(PolicyArn=policy_arn)
	return description['Policy']

def get_policy_document(policy_arn, version):
	policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version)
	return policy_document['PolicyVersion']['Document']

def document_has_permission(document, permission):
	statements = document['Statement']
	return any(permission in statement['Action'] for statement in statements)

def documents_have_permission(documents, permission):
	return any(document_has_permission(document, permission) for document in documents)

#document = {'Statement': [{'Action': ['logs:*'], 'Effect': 'Allow', 'Resource': 'arn:aws:logs:*:*:*'}, {'Action': ['ecs:DescribeServices', 'ecs:UpdateService'], 'Effect': 'Allow', 'Resource': ['*']}], 'Version': '2012-10-17'}
#permission = 'ecs:DescribeServices'

#print(document_has_permission(document, permission)) -> True

def role_has_permissions(role_name, permissions):
	'''
	:type permissions: list(string)
	:param permissions: list of permissions that need to be
		checked for a given role. Each of the permissions
		must be a string following AWS permissions notation,
		e.g. 'ecs:DescribeServices'.
	'''
	policies  = get_role_attached_policies(role_name)
	policies_descriptions = [describe_policy(policy['PolicyArn']) for policy in policies]
	policies_documents = [get_policy_document(policy['Arn'], policy['DefaultVersionId']) for policy in policies_descriptions]
	return all(documents_have_permission(policies_documents, permission) for permission in permissions)

def roles_have_permissions(roles, permissions):
	return filter(role_has_permissions(role, permissions) for role in roles)

#description = describe_policy(policy_arn)
#print(description) 

#version = description['DefaultVersionId']

#policy_document = get_policy_document(policy_arn, version)
#print(policy_document)

#document = policy_document['Document']

#print(document)

#doc_statements = document['Statement']

#for statement in doc_statements:
#	print(statement['Action'])

#documents = role_has_permissions('lambda_ecs_role', ['ecs:DescribeServices', 'ecs:UpdateService'])
#print(documents) -> True

