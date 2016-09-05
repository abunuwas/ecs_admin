import boto3
import uuid
import datetime
import random 
import json
import time
from zipfile import ZipFile
import os
from io import BytesIO

from botocore.exceptions import ClientError

from ec2 import list_instance_profiles

# Access parameters for setting everything up. 
# This must be admin-level. 
aws_access_parameters = {
	'aws_access_key_id': '',
	'aws_secret_access_key': '',
	'region_name': ''
}

#ecs_client = boto3.client('ecs', **aws_access_parameters)
#iam_client = boto3.client('iam', **aws_access_parameters)
#cloudwatch_client = boto3.client('cloudwatch', **aws_access_parameters)


# Get AWS clients and resources 
ecs_client = boto3.client('ecs')
iam_client = boto3.client('iam')
cloudwatch_client = boto3.client('cloudwatch')
lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')
sns_client = boto3.client('sns')


def test_metric_alarm(namespace=None, metric_name=None, metric_values=None, alarm=None):
	for value in metric_values:
		log_metric(namespace=namespace, metric_name=metric_name, metric_value=value)
		print('logged {}'.format(value))
		time.sleep(1)
	cloudwatch_client.set_alarm_state(AlarmName=alarm,
									StateValue='OK',
									StateReason='Test finished, back to OK state.')


if __name__ == '__main__':
	'''
	create_scaleup_alarm()
	create_scaledown_alarm()
	metrics = cloudwatch_client.list_metrics()
	print(metrics)
	for metric in metrics['Metrics']:
		for data in metric['Dimensions']:
			print(data)
	
	now = datetime.datetime.now() - datetime.timedelta(hours=3)
	for i in range(65):
		#now += datetime.timedelta(minutes=1)
		now = datetime.datetime.now() - datetime.timedelta(hours=1)
		value=random.randint(50,100)
		response = log_metric(date=now, value=value)
		print(response)
		print(now)
		print(value)
		time.sleep(1)
	'''
	#task_role = create_role(path='/xmpp_component', 
	#						role_name='xmpp_component_task_staging', 
	#						policy_doc=task_role_policy_document)
	#lambda_role = create_role(role_name='lambda_scaleup',
	#						policy_doc=)
	#lambda_role = create_role(name='lambda_ecs_role', policy=lambda_role_trust_policy)
	#print(lambda_role)
	'''
	response = delete_lambda('xmpp_component_scaleup')
	print(response)
	function = create_lambda(name='xmpp_component_scaleup',
							role='arn:aws:iam::876701361933:role/lambda_ecs_role',
							handler='.lambda_scaleuplambda_handler',
							code_file=os.path.abspath('lambda_scaleup.py'),
							description='A lambda function to increase the number of components running in the cluster.'
							)
	print(function)
	'''
	#response = update_lambda(name='xmpp_component_scaleup', code_file='lambda_scaleup.py')
	#print(response)
	
	#functions = list_lambdas()
	#print(functions)
	#policy = create_policy(policy_name='lambda_ecs', 
	#						policy_document=lambda_ecs_policy, 
	#						description='Policy allowing Lambda functions to describe and update ECS services'
	#						)
	#print(policy)
	#role = attach_policy(name='lambda_ecs_role', policy_arn='arn:aws:iam::876701361933:policy/lambda_ecs')
	#print(role)
	'''
	permission = lambda_client.add_permission(FunctionName='xmpp_component_scaleup',
								StatementId='aStatement',
								Action='lambda:InvokeFunction',
								Principal='sns.amazonaws.com')
	print(permission)
	'''
	#response = delete_sns_topic('arn:aws:sns:eu-west-1:876701361933:xmpp_component_scaleup')
	#print(response)
	#topic, subscription = create_notification(name='xmpp_component_scaleup_sns', protocol='lambda', endpoint='arn:aws:lambda:eu-west-1:876701361933:function:xmpp_component_scaleup')
	#print(topic)
	#print(subscription)
	'''
	scaleup_alarm = create_alarm(name='xmpp_component_queue_size_increase',
								 description='Increase desiredCount of xmpp_component_service by 1 when queue_size averages to more than 50 for 1 minute.',
								 actions=True,
								 alarm=['arn:aws:sns:eu-west-1:876701361933:xmpp_component_scaleup'],
								 metric_name='queue_size',
								 period=60,
								 threshold=50,
								 comparison_opt='GreaterThanOrEqualToThreshold'
								 )
	print(scaleup_alarm)
	'''
	#roles = iam_client.list_roles()
	#for role in roles['Roles']:
	#	print('Path: {} --- Name: {} --- Arn: //'.format(role['Path'], role['RoleName'], role['Arn']))
	#queue_size_increase_alarm = create_scaleup_alarm()
	'''
	cloudwatch_client.set_alarm_state(AlarmName='xmpp_component_queue_size_increase',
									StateValue='ALARM',
									StateReason='Setting the alarm in ALARM state for testing.')
	time.sleep(60)
	cloudwatch_client.set_alarm_state(AlarmName='xmpp_component_queue_size_increase',
									StateValue='OK',
									StateReason='Test finished, back to OK state.')
	'''
	#print(task_role_policy_document)
	#task_role = create_role()
	#print(task_role)
	#cluster = create_cluster()
	#print(cluster)
	#task = create_task_definition()
	#print(task)

	#ec2_instance_role = create_role(name='ec2InstanceRole', policy=ec2_trust_policy)
	#print(ec2_instance_role)


	#list_roles()
	#service = create_service()
	#print(service)

	#ecs_policy = create_policy(policy_name='ecs_role_policy', policy_document=ecs_role_policy)
	#print(ecs_policy)

	#policies = iam_client.list_policies()['Policies']
	#for policy in policies:
	#	print(policy['PolicyName'], policy['Arn'])

	#response = attach_policy(name='ec2InstanceRole', policy_arn='arn:aws:iam::876701361933:policy/ecs_role_policy')
	#print(response)

	#response = register_ec2()
	#print(response)

	#arn:aws:iam::876701361933:role/ec2InstanceRole

	# Create security group allowing external connectivity

	# Include ec2InstanceRole into the group

	# 

	#profile = create_instance_profile()
	#print(profile)

	#response = add_role2profile()
	#print(response)

	#profiles = iam_client.list_instance_profiles()['InstanceProfiles']
	#for p in profiles:
	#	if p['InstanceProfileName'] == 'ec2InstanceProfileECS': print(p['Roles'][0])

	#instance = launch_ec2()
	#print(instance)

	#response = create_task_definition()
	#print(response)

	#tasks = list_task_definitions()
	#print(tasks)

	#description = describe_task_definition(family='xmpp_component_2')
	#print(description['revision'])

	#service = update_service(cluster='xmpp_component_cluster', 
	#							service='xmpp_component_service', 
	#							desired_count=2, 
	#							task_definition=None)
	#print(service)


	high_values = (random.randint(51,100) for i in range(65))
	low_values = (random.randint(0,49) for i in range(65))
	#test_metric_alarm(namespace='xmpp_component', metric_name='queue_size', metric_values=high_values, alarm='xmpp_component_queue_size_increase')

	profiles = list_instance_profiles()
	for profile in profiles:
		print(profile['InstanceProfileName'])

	'''
	metrics = cloudwatch.list_metrics()
	for metric in metrics:
		print(metric)
	'''