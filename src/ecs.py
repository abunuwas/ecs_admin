import os
import uuid
import time

import boto3
from botocore.exceptions import ClientError

from ec2 import EC2Client
from core_utils import filter_args, filter_args_deep
from exceptions import InvalidOperationError, DoesNotExistError

class ECS:
	"""
	"""

	def __init__(self, aws_parameters=None):
		self.aws_parameters = aws_parameters
		self._make_clients()

		ec2_client = EC2Client()


	def _make_clients(self):
		if self.aws_parameters is not None:
			self.ecs_client = boto3.client('ecs', **self.aws_parameters)
		else:
			try:
				self.ecs_client = boto3.client('ecs')
			except Exception as e:
				print(str(e))
		return None 

	def create_cluster(self, name=None):
		cluster = self.ecs_client.create_cluster(clusterName=name)
		return cluster['cluster']

	def list_clusters(self):
		clusters = self.ecs_client.list_clusters()
		return clusters['clusterArns']

	def describe_cluster(self, cluster_name=None):
		cluster = list(filter(lambda cluster: cluster_name in cluster, self.list_clusters()))
		details = self.ecs_client.describe_clusters(clusters=cluster)
		return details['clusters'][0]

	def describe_clusters(self):
		clusters = self.list_clusters()
		details = self.ecs_client.describe_clusters(clusters=clusters)
		return details['clusters']

	def list_instances(self, cluster=None):
		instances = self.ecs_client.list_container_instances(cluster=cluster)
		return instances['containerInstanceArns']

	def _describe_instances(self, cluster):
		try:
			instances = self.ecs_client.describe_container_instances(cluster=cluster, containerInstances=self.list_instances(cluster))
		except ClientError as e:
			raise InvalidOperationError('Cluster {} containes 0 instances. No instance to describe.'.format(cluster))
		return instances['containerInstances']

	def describe_instances(self, cluster):
		try:
			return self._describe_instances(cluster)
		except InvalidOperationError:
			return []

	def deregister_instance(self, cluster, instance):
		response = self.ecs_client.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
		return response 

	def deregister_instances(self, cluster, instances):
		for instance in instances:
			deregister_instance(cluster, instance)
			print('ECS agent deregistered instance: {}'.format(instance))
			time.sleep(1)
		return None

	def delete_cluster(self, cluster):
		response = self.ecs_client.delete_cluster(cluster=cluster)
		return response

	def create_service(self, cluster, service_name, task_definition, desired_count=1, max_health=None, min_health=None, **kwargs):
		api_args = {
						'cluster': cluster,
						'serviceName': service_name,
						'taskDefinition': task_definition,
						'desiredCount': desired_count,
						'clientToken': str(uuid.uuid3(uuid.NAMESPACE_DNS, cluster)),
						'deploymentConfiguration': {
							'maximumPercent': max_health,
							'minimumHealthyPercent': min_health
						}
		}
		api_args.update(kwargs)
		args = filter_args_deep(api_args)
		try:
			service = self.ecs_client.create_service(**args)
			return service['service']
		except ClientError as e:
			return e

	def list_services(self, cluster):
		services = self.ecs_client.list_services(cluster=cluster)
		return services['serviceArns']

	def _describe_services(self, cluster):
		#services = [service.split('/')[1] for service in list_services(cluster)]
		try:
			services = self.list_services(cluster=cluster)
			descriptions = self.ecs_client.describe_services(cluster=cluster, services=services)
			return descriptions['services']
		except ClientError as e:
			if e.response['Error']['Code'] == 'ClusterNotFoundException':
				raise DoesNotExistError("Cluster {} does not exist. No services to describe.".format(cluster))

	def describe_services(self, cluster):
		try:
			return self._describe_services(cluster)
		except DoesNotExistError:
			return []

	def update_service(self, cluster, service, desired_count=1, task_definition=None, deployment_conf=None):
		service = self.ecs_client.update_service(cluster=cluster,
											service=service,
											desiredCount=desired_count
											#task_definition=
											)
		return service

	def set_count_services_zero(self, cluster, services):
		for service in services:
			self.update_service(cluster=cluster, service=service, desired_count=0, task_definition=None, deployment_conf=None)
		return None

	def delete_service(self, cluster, service):
		response = self.ecs_client.delete_service(cluster=cluster, service=service)
		return response 

	def delete_services(self, cluster, services):
		for service in services:
			self.delete_service(cluster, service)

	def stop_instances(self, instances):
		return ec2_client.stop_instances(instances=instances)

	def define_container(self, 
						 image, 
						 name, 
						 command=None, 
						 working_dir=None, 
						 cpu=100, 
						 memory=100, 
						 essential=True, 
						 disable_networking=None, 
						 privileged=None, 
						 readonly=True
						 ):
		api_args = { 
					'name': name,
					'image': image,
					'cpu': cpu,
					'memory': memory,
					#'memoryReservation': 200, # Minimum amount of memory reserved for the container
					#'links': [],
					#'portMappings': [],				'essential': essential,
					#'entryPoint': ['/application/src'],
					'command': command,
					#'environment': [],
					#'mountPoints': [],
					#'volumesFrom': [],
					#'hostname': '',
					#'user': '
					'workingDirectory': working_dir,
					'disableNetworking': disable_networking,
					'privileged': privileged,
					'readonlyRootFilesystem': readonly
					#'dnsServers': [],
					#'dnsSearchDomains': [],
					#'extraHosts': [],
					#'dockerSecurityOptions': [],
					#'dockerLabels': {},
					#'ulimits': [],
					#'logConfiguration': {},
					#'logDriver': '',
					#'options': {}				 
					}
		return filter_args(api_args, filter_params=['', None])

	def create_task_definition(self, family, containers, volumes=None):
		task_definition = self.ecs_client.register_task_definition(
			family=family, #families allow us to track multiple versions of the same task definition
			containerDefinitions=containers
			#volumes=[]
			)
		return task_definition['taskDefinition']

	def list_task_definitions(self, family=None):
		tasks = self.ecs_client.list_task_definitions(familyPrefix=family)['taskDefinitionArns']
		return tasks

	def describe_task_definition(self, family=None, revision=None):
		response = self.ecs_client.describe_task_definition(taskDefinition=family)['taskDefinition']
		return response 

	def deregister_task_def(self, task=None):
		response = self.ecs_client.deregister_task_definition(taskDefinition=task)
		return response 

	def list_tasks(self, cluster):
		tasks = self.ecs_client.list_tasks(cluster=cluster)
		return tasks['taskArns']

	def describe_tasks(self, cluster):
		tasks = self.list_tasks(cluster)
		descriptions = None
		try:
			descriptions = self.ecs_client.describe_tasks(cluster=cluster, tasks=tasks)
		except ClientError:
			print('No task is running.')
		finally: 
			return descriptions

	def stop_task(self, cluster, task):
		response = self.ecs_client.stop_task(cluster=cluster, task=task)
		return response 

	def stop_tasks(self, cluster):
		tasks = self.list_tasks(cluster)
		for task in tasks:
			stop_task(cluster, task)
		return None

	def clearup_cluster(self, cluster):
		# Still lacking functionality to remove associated metrics, alarms, lambdas, and sns topics
		services = self.list_services(cluster)
		self.set_count_services_zero(cluster, services)
		print('Number of desired tasks set to 0.')
		time.sleep(2)
		self.stop_tasks(cluster)
		print('Stopped running tasks.')
		time.sleep(2)
		tasks = self.list_tasks(cluster)
		for task in tasks:
			self.deregister_task_def(task)
		print('Deregistered all active tasks in the cluster.')
		time.sleep(1)
		self.delete_services(cluster, services)
		print('Deleted all services registered with the cluster.')
		time.sleep(1)
		cluster_instances = list(self.list_instances(cluster))
		self.deregister_instances(cluster, cluster_instances)
		print('Deregistered all container instances within the cluster.')
		time.sleep(1)
		try:
			self.stop_instances(cluster_instances)
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
		response = self.delete_cluster(cluster)
		print('Deleted cluster {}.'.format(cluster))
		return response 


ecs = ECS()

#clusters = ecs.list_clusters()
#print(clusters)

#instances = ecs.describe_instances('xmpp_component_cluster')
#print(instances) if no instance is running -> []

#details = ecs.describe_clusters()
#print(details) -> [{'registeredContainerInstancesCount': 0, 'clusterName': 'xmpp_component_cluster', 'clusterArn': 'arn:aws:ecs:eu-west-1:876701361933:cluster/xmpp_component_cluster', 'runningTasksCount': 0, 'activeServicesCount': 1, 'status': 'ACTIVE', 'pendingTasksCount': 0}, {'registeredContainerInstancesCount': 0, 'clusterName': 'xmpp_component_cluster_1', 'clusterArn': 'arn:aws:ecs:eu-west-1:876701361933:cluster/xmpp_component_cluster_1', 'runningTasksCount': 0, 'activeServicesCount': 0, 'status': 'ACTIVE', 'pendingTasksCount': 0}]

#details = ecs.describe_cluster('xmpp_component_cluster')
#print(details) -> {'clusterArn': 'arn:aws:ecs:eu-west-1:876701361933:cluster/xmpp_component_cluster', 'pendingTasksCount': 0, 'clusterName': 'xmpp_component_cluster', 'status': 'ACTIVE', 'activeServicesCount': 1, 'runningTasksCount': 0, 'registeredContainerInstancesCount': 0}

#definition = ecs.define_container('image', 'name')
#print(definition) #-> {'readonlyRootFilesystem': True, 'name': 'name', 'cpu': 100, 'image': 'image', 'memory': 100, 'essential': True}

#task_defs = ecs.list_task_definitions(family='xmpp_component')
#for task in task_defs:
#	print(task)
#print(task_defs[0]) #-> arn:aws:ecs:eu-west-1:876701361933:task-definition/xmpp_component:1

#cluster = ecs.create_cluster('xmpp_component_cluster_1')

#if not ecs.list_services('xmpp_component_cluster_1'):
#	print('No services found.') -> 'No services found.'

#for service in ecs.list_services('xmpp_component_cluster'):
#	print(service) 
#-> arn:aws:ecs:eu-west-1:876701361933:service/xmpp_component_service
