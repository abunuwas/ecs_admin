import boto3
ecs_client = boto3.client('ecs')


def create_cluster(name=None):
	cluster = ecs_client.create_cluster(clusterName=name)
	return cluster

def list_clusters():
	clusters = ecs_client.list_clusters()
	return clusters['clusterArns']

def describe_cluster(cluster_name=None):
	cluster = list(filter(lambda cluster: cluster_name in cluster, list_clusters()))
	details = ecs_client.describe_clusters(clusters=cluster)
	return details['clusters'][0]

def describe_clusters():
	clusters = list_clusters()
	details = ecs_client.describe_clusters(clusters=clusters)
	return details['clusters']

def list_instances(cluster=None):
	instances = ecs_client.list_container_instances(cluster=cluster)
	return instances['containerInstanceArns']

def describe_instances(cluster=None):
	instances = ecs_client.describe_container_instances(cluster=cluster, containerInstances=list_instances(cluster))
	return instances['containerInstances']

def deregister_instance(cluster, instance):
	response = ecs_client.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
	return response 

def deregister_instances(cluster, instances):
	for instance in instances:
		deregister_instance(cluster, instance)
		print('ECS agent deregistered instance: {}'.format(instance))
		time.sleep(1)
	return None

def delete_cluster(cluster):
	response = ecs_client.delete_cluster(cluster=cluster)
	return response

#clusters = list_clusters()
#print(clusters)

#instances = describe_instances('xmpp_component_cluster')
#print(instances)

#details = describe_clusters()
#print(details)

#details = describe_cluster('xmpp_component_cluster')
#print(details)



def create_service():
	service = ecs_client.create_service(
		cluster='xmpp_component_cluster',
		serviceName='xmpp_component_service',
		taskDefinition='xmpp_component_1:1',
		desiredCount=1,
		#role='arn:aws:iam::876701361933:role/ec2InstanceRole', # 'ecs_role' | 'ecs_xmpp_component_role'
		clientToken=str(uuid.uuid3(uuid.NAMESPACE_DNS, 'xmpp_component_cluster')),
		deploymentConfiguration={
			'maximumPercent': 150,
			'minimumHealthyPercent': 50
			}
		)

def list_services(cluster):
	services = ecs_client.list_services(cluster=cluster)
	return services['serviceArns']

def describe_services(cluster):
	#services = [service.split('/')[1] for service in list_services(cluster)]
	services = list_services(cluster)
	descriptions = ecs_client.describe_services(cluster=cluster, services=services)
	return descriptions['services']

def update_service(cluster=None, service=None, desired_count=1, task_definition=None, deployment_conf=None):
	service = ecs_client.update_service(cluster=cluster,
										service=service,
										desiredCount=desired_count
										#task_definition=
										)
	return service

def set_count_services_zero(cluster=None, services=None):
	for service in services:
		update_service(cluster=cluster, service=service, desired_count=0, task_definition=None, deployment_conf=None)
	return None

def delete_service(cluster=None, service=None):
	response = ecs_client.delete_service(cluster=cluster, service=service)
	return response 

def delete_services(cluster=None, services=None):
	for service in services:
		delete_service(cluster, service)






def create_task_definition():
	task_definition = ecs_client.register_task_definition(
		family='xmpp_component_2', #families allow us to track multiple versions of the same task definition
		#taskRoleArn=task_role_arn, # The task role that the containers in this task will assume. 
		#networkMode='', # bridge | host | none,
		containerDefinitions=[
			{
				'name': 'xmpp_component',
				'image': 'abunuwas/xmpp-component:v.0.0.1',
				'cpu': 100, # No idea...
				'memory': 100, # The Docker daemon reserves a min. of 4 MiB for containers. If the container exceeds this threshold, it's killed, so this represents a hard max. limit of mem use
				#'memoryReservation': 200, # Minimum amount of memory reserved for the container
				#'links': [],
				#'portMappings': [],
				'essential': True,
				#'entryPoint': ['/application/src'],
				'command': ['python3, application.py'],
				#'environment': [],
				#'mountPoints': [],
				#'volumesFrom': [],
				#'hostname': '',
				#'user': '',
				'workingDirectory': '/application',
				'disableNetworking': False,
				'privileged': False,
				'readonlyRootFilesystem': True
				#'dnsServers': [],
				#'dnsSearchDomains': [],
				#'extraHosts': [],
				#'dockerSecurityOptions': [],
				#'dockerLabels': {},
				#'ulimits': [],
				#'logConfiguration': {},
				#'logDriver': '',
				#'options': {}
				},
			],
		#volumes=[]
		)

def list_task_definitions():
	tasks = ecs_client.list_task_definitions()['taskDefinitionArns']
	return tasks

def describe_task_definition(family=None, revision=None):
	response = ecs_client.describe_task_definition(taskDefinition=family)['taskDefinition']
	return response 

def deregister_task_def(task=None):
	response = ecs_client.deregister_task_definition(taskDefinition=task)
	return response 


def list_tasks(cluster):
	tasks = ecs_client.list_tasks(cluster=cluster)
	return tasks['taskArns']

def describe_tasks(cluster):
	tasks = list_tasks(cluster)
	descriptions = None
	try:
		descriptions = ecs_client.describe_tasks(cluster=cluster, tasks=tasks)
	except ClientError:
		print('No task is running.')
	finally: 
		return descriptions

def stop_task(cluster=None, task=None):
	response = ecs_client.stop_task(cluster=cluster, task=task)
	return response 

def stop_tasks(cluster):
	tasks = list_tasks(cluster)
	for task in tasks:
		stop_task(cluster, task)
	return None
