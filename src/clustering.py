import boto3

from ecs import ECS
from ec2 import EC2Instance
from iam import IAM
from sns import SNS
from lambda_func import Lambda
from core_utils import filter_args
#from exceptions import EntityExistsError, LimitExceededError, DoesNotExistError, MissingValueError, InvalidOPerationError

class Cluster(ECS):
	"""
	"""

	def __init__(self, app_name, aws_parameters=None):
		self.app_name = app_name 
		self.aws_parameters = aws_parameters
		self._make_clients()
		self.ec2 = EC2Instance(None, None, None)
		self.iam = IAM()
		self.sns = SNS()
		self.awslambda = Lambda()

	def _make_clients(self):
		if self.aws_parameters is not None:
			self.ecs_client = boto3.client('ecs', **self.aws_parameters)
		else:
			try:
				self.ecs_client = boto3.client('ecs')
			except Exception as e:
				print(str(e))
		return None 

	def create(self):
		pass

	def clearup(self):
		pass

	def list_task_definitions(self):
		return ECS.list_task_definitions(self, self.app_name)

	def list_roles(self, **kwargs):
		roles = self.iam.list_roles(**kwargs)
		return roles

	def role_has_permission(self, role_name, permissions):
		return self.iam.role_has_permission(role_name, permissions)

	def roles_have_permissions(self, roles, permissions):
		return self.iam.roles_have_permissions(roles, permissions)

	def list_policies(self, **kwargs):
		return self.iam.list_policies(**kwargs)

	def default_ec2_instance_profile(self):
		ecs_instance_role = create_role(role_name='ec2InstanceRole', policy_trust=ec2_trust_policy)
		ecs_policy = create_policy(policy_name='ecs_role_policy', policy_document=ecs_role_policy)
		attach_policy(role_name='ec2InstanceRole', policy_arn=ecs_policy)
		profile = create_instance_profile(name='ec2InstanceProfileECS')
		response = add_role2profile(role_name='ec2InstanceRole',
									profile_name='ec2InstanceProfileECS')
		return profile

	def default_ecs_lambda_role(self):
		#lambda_role = iam_client.create_role(role_name='lambda_ecs_role', policy_trust=task_role_policy)
		#lambda_ecs_policy = iam_client.create_policy(policy_name='lambda_ecs',
		#												policy_document=lambda_ecs_policy,
		#												description='Standard policy allowing Lambda functions to describe and update ECS services.'
		#												)
		#if not role_has_permissions(lambda_role, permissions=['ecs:DescribeServices', 'ecs:UpdateService', 'logs:*']):
		#	iam_client.attach_policy('lambda_ecs_role', policy_arn=lambda_ecs_policy)
		#return None
		pass 

	def create_lambda(self, **kwargs):
		# return lambda_func.create_lambda(**kwargs)
		pass 

	def add_permission(self, **kwargs):
		# return lambda_client.add_permissions(**kwargs)
		pass 

	def create_notification(self, **kwargs):
		# return sns_client.create_notification(**kwargs)
		pass 

	def create_default_scaleup_lambda(self, metric_):
		default_notification_scaleupdown = None 
		pass

	def create_default_scaledown_lambda(self):
		pass

	def create_default_lambdas(self):
		create_default_scaleup_lambda()
		create_default_scaledown_lambda()

	def create_alarm(self, **kwargs):
		# return cloudwatch_client.create_alarm(**kwargs)
		pass 

	def set_alarm_state(self, **kwargs):
		# return cloudwatch_client.set_alarm_state(**kwargs)
		pass 

	def list_resources(self):
		cluster_name = None
		task_definitions = None
		running_tasks = None
		service = { 
					'service_name': None,
					'desired_count': 0, 
					'running_tasks': 0, 
					'pending_tasks': 0, 
					'deployment_config': { 
											'min_health': 0, 
											'max_health': 0
											} 
					}
		lambdas = []
		metrics = None
		alarms = None
		sns_topics = None
		ec2 = []

	def launch_ec2(self, key_name, security_groups, user_data, profile_arn, min_count=1, max_count=1, instance_type='t2.micro', monitoring=True):
		# ec2_client.launch_instance()
		instance = launch_ec2(values())
		return instance

	def setup_cluster(self, 
					  app_name='xmpp_component', 
					  lambda_ecs='lambda_ecs_role', 
					  image='abunuwas/xmpp-component:v.0.0.1', 
					  desired_count=1,
					  max_health=150,
					  min_health=50,
					  user_data_file='docker-login.txt'
					  ):
		cluster_name = app_name+'_cluster'
		service_name = app_name+'_service'
		task_name = app_name+'_task'
		#lambda_role = lambda_ecs
		key_name = 'ecs_cluster'
		security_groups = ['testxmpp']
		user_data = get_user_data(user_data_file)

		cluster = create_cluster(cluster_name)

		task_role = create_role(path=app_name,
								role_name=task_name,
								policy_trust=task_role_policy)

		container = define_container(name=app_name, image=image)

		task_definition = create_task_definition(family=app_name, containers=[container])

		service = create_service(cluster=cluster_name, 
								 service_name=service_name, 
								 task_definition=list_task_definitions(family=app_name)[-1], 
								 desired_count=desired_count, 
								 max_health=max_health,
								 min_health=min_health
								 )

		profile = default_ec2_instance_profile()

		return profile 



cluster_name = 'xmpp_component'

cluster = Cluster(cluster_name)

#roles = cluster.list_roles()
#for role in roles:
#	print(role)
#roles_names = [role['RoleName'] for role in roles]
#print('aws-elasticbeanstalk-ec2-role' in roles_names)

#services = cluster.list_services(cluster_name)
#print(services) # -> ['arn:aws:ecs:eu-west-1:876701361933:service/xmpp_component_service']

#tasks = cluster.list_tasks(cluster_name)
#print(tasks) #-> []

#definitions = cluster.list_task_definitions()
#print(definitions)
#print('arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:1' in definitions)

#descriptions = [cluster.describe_task_definition(definition) for definition in definitions]
#print(descriptions[0])
# -> {'volumes': [], 'requiresAttributes': [{'name': 'com.amazonaws.ecs.capability.ecr-auth'}], 'revision': 1, 'status': 'ACTIVE', 'containerDefinitions': [{'portMappings': [{'protocol': 'tcp', 'containerPort': 8080, 'hostPort': 9090}], 'essential': True, 'command': [], 'environment': [], 'cpu': 10, 'links': [], 'name': 'sample-app', 'memory': 300, 'mountPoints': [], 'image': '876701361933.dkr.ecr.eu-west-1.amazonaws.com/abunuwas/python_app:latest', 'volumesFrom': [], 'entryPoint': []}], 'taskDefinitionArn': 'arn:aws:ecs:eu-west-1:876701361933:task-definition/console-sample-app-static:1', 'family': 'console-sample-app-static'}

services_description = cluster.describe_services(cluster_name)
print(services_description[0].keys())
#service_task_def = services_description[0]['taskDefinition']
#print(service_task_def)
#service_task_def_description = describe_task_definition(service_task_def)
#print(service_task_def_description)
#set_count_services_zero(cluster, services)
#tasks_descriptions = describe_tasks(cluster)
#print(tasks_descriptions)
#response = stop_tasks(cluster)
#print(response)

#response = clearup_cluster(cluster)
#print(response)

#from ecs import create_cluster, define_container, create_task_definition, create_service, list_task_definitions
#from iam import create_role, list_roles, role_has_permissions, attach_policy, create_policy
#from lambda_func import create_lambda, add_permission
#from policies import task_role_policy, lambda_role_trust_policy, lambda_ecs_policy, ecs_role_policy, ec2_trust_policy
#from ec2 import launch_ec2, get_user_data, create_instance_profile, add_role2profile

#from iam import IAM
#iam_client = IAM()

#instance = launch_ec2(key_name=key_name, security_groups=security_groups, user_data=, profile_arn=user_data)

#provision_default_ecs_lambda_role()

#lambda_role = create_role(role_name=lambda_role,
#							policy_trust=lambda_role_trust_policy)

#from policies import lambda_ecs_policy

#lambda_ecs_policy = create_policy(policy_name='lambda_ecs_test',
#									policy_document=lambda_ecs_policy,
#									description='Standard policy allowing Lambda functions to describe and update ECS services.'
#									)

#permission = add_permission(function_name='lambda_ecs', 
	#if not role_has_permissions(role_name=lambda_ecs, permissions=['ecs:DescribeServices', 'ecs:UpdateService', 'logs:*']):
	#request = attach_policy()

#provision_ecs_lambda_role(lambda_role_name=lambda_ecs)

#function = create_lambda(name=lambda_name+'_scaleup',
#							role_arn=lambda_role,
#							handler=handler,
#							code_file=code_file,
#							description=description
#							)

#test = setup_cluster(lambda_ecs='lambda_ecs_role')
#print(test)



