from __future__ import print_function

import json

import boto3

ecs_client = boto3.client('ecs', region_name='eu-west-1')

def update_service(cluster=None, 
                    service=None, 
                    desired_count=1, 
                    task_definition=None, 
                    deployment_conf=None):
	service = ecs_client.update_service(cluster=cluster,
										service=service,
										desiredCount=desired_count
										)
	return service
	
def describe_service(service_name=None, cluster=None):
	services = ecs_client.describe_services(cluster=cluster,
							services=[service_name])['services'][0]
	return services

def lambda_handler(event=None, context=None):
    cluster = 'xmpp_component_cluster'
    service = describe_service(cluster=cluster,
                                        service_name='xmpp_component_service')
    count = service['desiredCount']
    count += 1
    response = update_service(cluster=cluster, 
                              service='xmpp_component_service',
                              desired_count=count)
    return 'Scaled cluster with one additional container'