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

	def __init__(self, 
				 app_name, 
				 image, 
				 task_definition=None,
				 service=None,
				 desired_count=1, 
				 max_health=None, 
				 min_health=None, 
				 container_definitions=None,
				 key_name=None,
				 security_groups=None,
				 user_data_file=None,
				 user_data=None,
				 lambda_role=None, 
				 aws_parameters=None
				 ):
		'''

		:type max_health: int
		:param max_health: maximumPercent for the deployment 
			configuration of an ECS service. Default value in 
			the AWS API is 200.

		:type min_health: int
		:param min_health: minimumHealthyPercent for the deployment 
			configuration of an ECS service. Default value in the 
			AWS API is 50. 

		:type key_name: string
		:param key_name: name of the ssh key pair to be used when 
			creating EC2 instances within the cluster.b 
		'''
		self.app_name = app_name 

		# The following parameters are automatically assigned
		# based on the name of the application following a 
		# default naming structure. This is to ensure that we 
		# follow a systematic and ordered approachto naming our 
		# resources that makes it easier to identify and locate 
		# them. 
		# Users are free to modify these attributes by repointing
		# them to different strings. This might be warranted in
		# cases in which some flexibility is required. For this
		# reason, the attributes are not readonly. 
		# Users who modify these attributes are responsible for
		# keeping track of the resources they create associated
		# with the cluster. 
		self.cluster_name = app_name+'_cluster'
		self.service_name = app_name+'_service'
		self.task_name = app_name+'_task'
		if container_definitions is None:
			self.container_definitions = []
		else:
			self.container_definitions = container_definitions
		self.task_definition = task_definition
		self.service = service

		self.image = image
		self.desired_count = desired_count
		self.min_health = min_health
		self.max_health = max_health

		self.key_name = key_name
		self.user_data_file = user_data_file
		self.user_data = user_data
		self.security_groups = security_groups

		self.lambda_role = lambda_role
		#self.default_lambda_role = 'lambda_ecs_role'

		self.aws_parameters = aws_parameters
		self._make_clients()
		self.ec2 = EC2Instance(None, None, None)
		self.iam = IAM()
		self.sns = SNS()
		self.awslambda = Lambda()

		self._cluster = None

	@property
	def cluster(self):
		return self._cluster
	

	def _make_clients(self):
		if self.aws_parameters is not None:
			self.ecs_client = boto3.client('ecs', **self.aws_parameters)
		else:
			try:
				self.ecs_client = boto3.client('ecs')
			except Exception as e:
				print(str(e))
		return None 

	def get_ready(self):
		cluster = self.create_cluster()
		self.define_container()
		self.create_task_definition()
		self.create_service()
		self.user_data = ec2.get_user_data(self.user_data_file)

	def create(self):
		#lambda_role = lambda_ecs

		#task_role = self.create_role(path=self.app_name,
		#						role_name=self.task_name,
		#						policy_trust=task_role_policy)

		profile = default_ec2_instance_profile()

		return profile 

	def clearup(self):
		pass

	def create_cluster(self):
		cluster = ECS.create_cluster(self, name=self.cluster_name)
		self._cluster = cluster['clusterArn']
		return self.cluster

	def define_container(self, image=None, name=None, **kwargs):
		if image is None:
			image = self.image
		if name is None:
			name = self.app_name
		container = ECS.define_container(self, image=image, name=name, **kwargs)
		self.container_definitions.append(container)
		return None

	def create_task_definition(self, *args, **kwargs):
		task_definition = ECS.create_task_definition(self, family=self.app_name, containers=self.container_definitions, **kwargs)
		self.task_definition = task_definition['taskDefinitionArn']
		return self.task_definition

	def list_task_definitions(self):
		return ECS.list_task_definitions(self, self.app_name)

	def list_tasks(self, *args, **kwargs):
		return ECS.list_tasks(self, self.cluster_name)

	def describe_tasks(self):
		return ECS.describe_tasks(self, self.cluster_name)

	def stop_tasks(self, *args, **kwargs):
		return ECS.stop_tasks(self, cluster=self.cluster_name)

	def create_service(self, **kwargs):
		service = ECS.create_service(self, 
									 cluster=self.cluster_name, 
									 service_name=self.service_name, 
									 task_definition=self.task_definition, 
									 desired_count=self.desired_count,
									 max_health=self.max_health,
									 min_health=self.min_health,
									 **kwargs
									 )
		self.service = service['serviceArn']
		return self.service

	def list_services(self, *args, **kwargs):
		return ECS.list_services(self, cluster=self.cluster_name)

	def describe_services(self):
		return ECS.describe_services(self, self.cluster_name)

	def set_count_services_zero(self, *args, **kwargs):
		return ECS.set_count_services_zero(self, cluster=self.cluster_name, services=self.list_services())

	def delete_service(self, service, *args, **kwargs):
		return ECS.delete_service(self, cluster=self.cluster_name, service=service)

	def delete_services(self, services, *args, **kwargs):
		return ECS.delete_services(self, cluster=self.cluster_name, services=services)

	def delete(self):
		return ECS.delete_cluster(self, cluster=self.cluster_name)

	def clearup(self):
		return ECS.clearup_cluster(self, self.cluster_name)

	def create_role(self, **kwargs):
		return iam.create_role(**kwargs)

	def list_roles(self, **kwargs):
		return self.iam.list_roles(**kwargs)

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

	def launch_ec2(self, key_name, security_groups, profile_arn):
		# ec2_client.launch_instance()
		instance = launch_ec2(values())
		return instance



cluster_name = 'xmpp_component'

cluster = Cluster(app_name=cluster_name, image='abunuwas/xmpp-component:v.0.0.1')
cluster.get_ready()

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


#roles = cluster.list_roles()
#for role in roles:
#	print(role)
#roles_names = [role['RoleName'] for role in roles]
#print('aws-elasticbeanstalk-ec2-role' in roles_names)

#services = cluster.list_services()
#print(services) # -> ['arn:aws:ecs:eu-west-1:876701361933:service/xmpp_component_service']

#tasks = cluster.list_tasks(cluster_name)
#print(tasks) #-> []

#definitions = cluster.list_task_definitions()
#print(definitions)
#print('arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:1' in definitions)

#descriptions = [cluster.describe_task_definition(definition) for definition in definitions]
#print(descriptions[0])
# -> {'volumes': [], 'requiresAttributes': [{'name': 'com.amazonaws.ecs.capability.ecr-auth'}], 'revision': 1, 'status': 'ACTIVE', 'containerDefinitions': [{'portMappings': [{'protocol': 'tcp', 'containerPort': 8080, 'hostPort': 9090}], 'essential': True, 'command': [], 'environment': [], 'cpu': 10, 'links': [], 'name': 'sample-app', 'memory': 300, 'mountPoints': [], 'image': '876701361933.dkr.ecr.eu-west-1.amazonaws.com/abunuwas/python_app:latest', 'volumesFrom': [], 'entryPoint': []}], 'taskDefinitionArn': 'arn:aws:ecs:eu-west-1:876701361933:task-definition/console-sample-app-static:1', 'family': 'console-sample-app-static'}

services_description = cluster.describe_services()
#print(services_description)
# -> [{'deployments': [{'createdAt': datetime.datetime(2016, 9, 6, 15, 45, 16, 690000, tzinfo=tzlocal()), 'runningCount': 0, 'desiredCount': 1, 'updatedAt': datetime.datetime(2016, 9, 6, 15, 45, 16, 690000, tzinfo=tzlocal()), 'taskDefinition': 'arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:7', 'status': 'PRIMARY', 'id': 'ecs-svc/9223370563678059106', 'pendingCount': 0}], 'runningCount': 0, 'deploymentConfiguration': {'minimumHealthyPercent': 50, 'maximumPercent': 150}, 'taskDefinition': 'arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:7', 'createdAt': datetime.datetime(2016, 9, 6, 15, 45, 16, 690000, tzinfo=tzlocal()), 'events': [{'createdAt': datetime.datetime(2016, 9, 9, 3, 53, 34, 717000, tzinfo=tzlocal()), 'id': 'b140e3fb-b19a-4cff-baf4-a6a7a4589b58', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 8, 21, 52, 5, 574000, tzinfo=tzlocal()), 'id': '603c509d-ddf8-4ca5-a1c7-f6d5a8f6dc47', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 8, 15, 51, 24, 9000, tzinfo=tzlocal()), 'id': 'e9058d43-f508-4140-86b5-04cf5fe7bd44', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 8, 9, 51, 21, 866000, tzinfo=tzlocal()), 'id': '8eb52637-b583-4f53-aea1-3e17413eb2db', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 8, 3, 49, 46, 177000, tzinfo=tzlocal()), 'id': '6bb6c20a-0fcf-4e0b-87b6-15e77322013d', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 7, 21, 49, 16, 550000, tzinfo=tzlocal()), 'id': '8dba18ab-4dd9-40fe-93f0-72b453e35b4c', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 7, 15, 48, 42, 277000, tzinfo=tzlocal()), 'id': '137c846f-be76-4750-b376-c83eadf2387e', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 7, 9, 47, 43, 926000, tzinfo=tzlocal()), 'id': '0451faea-60be-4142-ac4c-7199e8c33dca', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 7, 3, 46, 25, 984000, tzinfo=tzlocal()), 'id': 'f2cd5a9e-e5e5-4777-a710-1a17481175f0', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 6, 21, 45, 55, 486000, tzinfo=tzlocal()), 'id': 'aac7c71f-cfb5-4e38-9b6a-a462061ee142', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}, {'createdAt': datetime.datetime(2016, 9, 6, 15, 45, 24, 646000, tzinfo=tzlocal()), 'id': 'b2238f4a-ee05-4cb4-801e-ca2a8e2b1d16', 'message': '(service xmpp_component_service) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide.'}], 'pendingCount': 0, 'loadBalancers': [], 'desiredCount': 1, 'serviceName': 'xmpp_component_service', 'clusterArn': 'arn:aws:ecs:eu-west-1:876701361933:cluster/xmpp_component_cluster', 'status': 'ACTIVE', 'serviceArn': 'arn:aws:ecs:eu-west-1:876701361933:service/xmpp_component_service'}]

service_task_def = services_description[0]['taskDefinition']
#print(service_task_def)
# -> arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:7

service_task_def_description = cluster.describe_task_definition(service_task_def)
#print(service_task_def_description)
# -> {'status': 'ACTIVE', 'revision': 7, 'requiresAttributes': [{'name': 'com.amazonaws.ecs.capability.docker-remote-api.1.17'}], 'family': 'xmpp_component', 'volumes': [], 'taskDefinitionArn': 'arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:7', 'containerDefinitions': [{'readonlyRootFilesystem': True, 'volumesFrom': [], 'mountPoints': [], 'image': 'abunuwas/xmpp-component:v.0.0.1', 'environment': [], 'memory': 100, 'name': 'xmpp_component', 'essential': True, 'cpu': 100, 'portMappings': []}]}


#cluster.set_count_services_zero()
#tasks_descriptions = cluster.describe_tasks()
#print(tasks_descriptions)
#response = cluster.stop_tasks()
#print(response)

#response = cluster.clearup()
#print(response)

