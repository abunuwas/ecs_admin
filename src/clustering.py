import boto3
def clearup_cluster(cluster):
	# Still lacking functionality to remove associated metrics, alarms, lambdas, and sns topics
	services = list_services(cluster)
	set_count_services_zero(cluster, services)
	print('Number of desired tasks set to 0.')
	time.sleep(2)
	stop_tasks(cluster)
	print('Stopped running tasks.')
	time.sleep(2)
	tasks = list_tasks(cluster)
	for task in tasks:
		deregister_task_def(task)
	print('Deregistered all active tasks in the cluster.')
	time.sleep(1)
	delete_services(cluster, services)
	print('Deleted all services registered with the cluster.')
	time.sleep(1)
	cluster_instances = list(list_instances(cluster))
	deregister_instances(cluster, cluster_instances)
	print('Deregistered all container instances within the cluster.')
	time.sleep(1)
	try:
		stop_instances(cluster_instances)
		print('Stopped container instances in the cluster.')
		time.sleep(5)
	except ClientError:
		print('No running instance within the cluster found.')
	try:
		terminate_instances(cluster_instances)
		print('Termianted container instances in the cluster, no instance to stop.')
		time.sleep(5)
	except ClientError:
		print('No running instance within the cluster found, no instance to terminate.')
	response = delete_cluster(cluster)
	print('Deleted cluster {}.'.format(cluster))
	return response 


cluster = 'xmpp_component_cluster'
#services = list_services(cluster)
#print(services)
#tasks = list_tasks(cluster)
#print(tasks)
#definitions = list_task_definitions()
#print('TASKS DEFINITIONS')
#for definition in definitions:
#	description = describe_task_definition(definition)
#	print(definition)
#	print(description)
#services_description = describe_services(cluster)
#print(services_description[0].keys())
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

from ecs import create_cluster, define_container, create_task_definition, create_service, list_task_definitions
from iam import create_role, list_roles, role_has_permissions, attach_policy, create_policy
from lambda_func import create_lambda, add_permission
from policies import task_role_policy, lambda_role_trust_policy, lambda_ecs_policy, ecs_role_policy, ec2_trust_policy
from ec2 import launch_ec2, get_user_data, create_instance_profile, add_role2profile

#from iam import IAM
#iam_client = IAM()

def list_roles(**kwargs):
	# roles = iam.list_roles(**kwargs)
	# return roles
	pass

def role_has_permission(role_name, permissions):
	# return iam.role_has_permission(role_name, permissions)
	pass 

def roles_have_permissions(roles, permissions):
	# return iam.roles_have_permissions(roles, permissions)
	pass

def list_policies(**kwargs):
	# return iam.list_policies(**kwargs)
	pass 

#def list_task_definitions():
#	pass 

def default_ec2_instance_profile():
	ecs_instance_role = create_role(role_name='ec2InstanceRole', policy_trust=ec2_trust_policy)
	ecs_policy = create_policy(policy_name='ecs_role_policy', policy_document=ecs_role_policy)
	attach_policy(role_name='ec2InstanceRole', policy_arn=ecs_policy)
	profile = create_instance_profile(name='ec2InstanceProfileECS')
	response = add_role2profile(role_name='ec2InstanceRole',
								profile_name='ec2InstanceProfileECS')
	return profile

def default_ecs_lambda_role():
	#lambda_role = iam_client.create_role(role_name='lambda_ecs_role', policy_trust=task_role_policy)
	#lambda_ecs_policy = iam_client.create_policy(policy_name='lambda_ecs',
	#												policy_document=lambda_ecs_policy,
	#												description='Standard policy allowing Lambda functions to describe and update ECS services.'
	#												)
	#if not role_has_permissions(lambda_role, permissions=['ecs:DescribeServices', 'ecs:UpdateService', 'logs:*']):
	#	iam_client.attach_policy('lambda_ecs_role', policy_arn=lambda_ecs_policy)
	#return None
	pass 

def create_lambda(**kwargs):
	# return lambda_func.create_lambda(**kwargs)
	pass 

def add_permission(**kwargs):
	# return lambda_client.add_permissions(**kwargs)
	pass 

def create_notification(**kwargs):
	# return sns_client.create_notification(**kwargs)
	pass 

def create_default_scaleup_lambda(metric_):
	default_notification_scaleupdown = None 
	pass

def create_default_scaledown_lambda():
	pass

def create_default_lambdas():
	create_default_scaleup_lambda()
	create_default_scaledown_lambda()

def create_alarm(**kwargs):
	# return cloudwatch_client.create_alarm(**kwargs)
	pass 

def set_alarm_state(**kwargs):
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

def launch_ec2(key_name, security_groups, user_data, profile_arn, min_count=1, max_count=1, instance_type='t2.micro', monitoring=True):
	# ec2_client.launch_instance()
	instance = launch_ec2(values())
	return instance

def setup_cluster(app_name='xmpp_component', 
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

	return profile 

test = setup_cluster(lambda_ecs='lambda_ecs_role')
print(test)



