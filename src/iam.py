import boto3
iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')


def create_policy(policy_name=None, path=None, policy_document=None, description=None):
	policy = iam_client.create_policy(PolicyName=policy_name,
										PolicyDocument=policy_document
										)
	return policy

auto_scaling_group = ''

def create_role(path=None, name=None, policy=None):
	'''
	:policy is a trust policy to be passed as an argument
	for the AssumeRolePolicyDocument variable in the 
	createRole API call of IAM. 
	'''
	role = iam_client.create_role(
		#Path='/xmpp_component_role/',
		RoleName=name,
		AssumeRolePolicyDocument=policy
		)
	return role

def list_roles():
	roles = iam_client.list_roles()['Roles']
	return roles

#roles = list_roles()
#for role in roles:
#	print(role.keys())
#	print(role['RoleName'], role['Arn'], role['AssumeRolePolicyDocument'])

def attach_policy(role_name=None, policy_arn=None):
	response = iam_client.attach_role_policy(role_name=name,
							PolicyArn=policy_arn)
	return response

def list_policies():
	policies = iam_client.list_policies()
	return policies['Policies']

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

#print(document_has_permission(document, permission))

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
	return documents_have_permission(policies_documents, permissions)

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

documents = role_has_permissions('lambda_ecs_role', 'ecs:DescribeServices')
print(documents)
#for doc in documents:
#	for statement in doc['Statement']:
#		print('ecs:DescribeServices' in statement['Action'])

