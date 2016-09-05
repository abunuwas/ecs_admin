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

from ecs import create_cluster
from iam import create_role, list_roles
from lambda_func import create_lambda
from policies import task_role_policy, lambda_role_trust_policy

def provision_ecs_lambda_role():
	roles = list_roles()
	return roles


def setup_cluster(app_name):
	cluster_name = app_name+'_cluster'
	service_name = app_name+'_service'
	task_name = app_name+'_task'
	lambda_name = app_name+'_lambda'

	cluster = create_cluster(cluster_name)

	task_role = create_role(path=app_name,
							role_name=task_name,
							policy_doc=task_role_policy)

	lambda_role = create_role(role_name=lambda_name,
								policy=lambda_role_trust_policy)

	function_scaleup = create_lambda(name=lambda_name+'_scaleup',
										role=None)



