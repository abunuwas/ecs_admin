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


# Get AWS clients 
ecs_client = boto3.client('ecs')
iam_client = boto3.client('iam')
cloudwatch_client = boto3.client('cloudwatch')
lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
#ec2_resource = boto3.resource('ec2')
sns_client = boto3.client('sns')

def subscribe_sns_topic(arn=None, protocol=None, endpoint=None):
	subscription = sns_client.subscribe(TopicArn=arn,
										Protocol=protocol,
										Endpoint=endpoint)
	return subscription['SubscriptionArn']

def create_notification(name=None, protocol=None, endpoint=None):
	topic = create_sns_topic(name)
	subscription = subscribe_sns_topic(arn=topic, protocol=protocol, endpoint=endpoint)
	return topic, subscription

def create_sns_topic(name=None):
	topic = sns_client.create_topic(Name=name)
	return topic['TopicArn']


def delete_sns_topic(arn=None):
	response = sns_client.delete_topic(TopicArn=arn)
	return response


def create_alarm(name=None, 
				 description=None, 
				 actions=True, 
				 ok=None, 
				 alarm=None, 
				 insufficient=None, 
				 metric_name=None,
				 namespace=None,
				 statistic=None,
				 period=None,
				 unit='Milliseconds',
				 evaluation_periods=1,
				 threshold=None,
				 comparison_opt=None):
	if ok is None:
		ok = []
	if alarm is None:
		alarm = []
	if insufficient is None:
		insufficient = []
	# Alarm to increase the number of components when queue size is bigger than 50
	cloudwatch_client.put_metric_alarm(
		AlarmName=name,
		AlarmDescription=description,
		ActionsEnabled=actions,
		OKActions=ok, # What to do when alarm transitions to OK state, e.g.: arn:aws:automate:region (e.g., us-east-1) :ec2:stop
		AlarmActions=alarm, # List of actions to take when the alarm transitions into an ALARM state, e.g.: arn:aws:automate:region (e.g., us-east-1) :ec2:recover
		InsufficientDataActions=insufficient, # What to do when the alarm transitions into INSUFFICIENT_DATA state, e.g.: arn:aws:swf:us-east-1:{customer-account }:action/actions/AWS_EC2.InstanceId.Reboot/1.0
		MetricName=metric_name,
		Namespace='xmpp_component',
		Statistic='Average', # Statistic to apply to the alarm's associated metric
		#Dimensions=[{'Name': 'xmpp_component', 'Value': 'scaleup'}],
		Period=period, # The period in seconds over which the statistic is applied: granularity? 
		Unit=unit, # Not sure what should going in here...
		EvaluationPeriods=evaluation_periods,
		Threshold=threshold,
		ComparisonOperator=comparison_opt
		)



def create_scaledown_alarm():
	# Alarm to decrease the number of containers when queue size is less than 20
	cloudwatch_client.put_metric_alarm(
		AlarmName='xmpp_component_queue_size_decrease',
		AlarmDescription='Decrease or decrease the number of containers based on queue size',
		ActionsEnabled=True,
		OKActions=[], # What to do when alarm transitions to OK state, e.g.: arn:aws:automate:region (e.g., us-east-1) :ec2:stop
		AlarmActions=[], # List of actions to take when the alarm transitions into an ALARM state, e.g.: arn:aws:automate:region (e.g., us-east-1) :ec2:recover
		InsufficientDataActions=[], # What to do when the alarm transitions into INSUFFICIENT_DATA state, e.g.: arn:aws:swf:us-east-1:{customer-account }:action/actions/AWS_EC2.InstanceId.Reboot/1.0
		MetricName='queue_size',
		Namespace='xmpp_component',
		Statistic='Minimum', # Statistic to apply to the alarm's associated metric
		Dimensions=[{'Name': 'xmpp_component', 'Value': 'scaledown'}],
		Period=60, # The period in seconds over which the statistic is applied: granularity? 
		Unit='Milliseconds', # Not sure what should going in here...
		EvaluationPeriods=6,
		Threshold=20,
		ComparisonOperator='LessThanOrEqualToThreshold'
		)

#task_role_policy_document = json.load(open('task_policy_xmpp_component.json'))
####### THIS IS ACTUALLY ECS AGENT POLICY!!!!!! fOR AmazonEC2ContainerServiceforEC2Role 
ecs_role_policy = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:CreateCluster",
        "ecs:DeregisterContainerInstance",
        "ecs:DiscoverPollEndpoint",
        "ecs:Poll",
        "ecs:RegisterContainerInstance",
        "ecs:StartTelemetrySession",
        "ecs:Submit*",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "s3:GetObject"
      ],
    "Resource": "arn:aws:ecs:eu-west-1:876701361933:cluster/xmpp_component_cluster"
    }
  ]
}'''

ec2_trust_policy = '''{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "sadf123456f3",
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'''


task_role_policy = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1465589882000",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": [
        "sts:AssumeRole"
      ]
    }
  ]
}'''

service_role_policy = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'''

lambda_role_trust_policy = '''{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "",
			"Effect": "Allow",
			"Principal": {
				"Service": "lambda.amazonaws.com"
			},
			"Action": "sts:AssumeRole"
		}
	]
}
'''

lambda_ecs_policy = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:*"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeServices",
        "ecs:UpdateService"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}'''



def update_service(cluster=None, service=None, desired_count=1, task_definition=None, deployment_conf=None):
	service = ecs_client.update_service(cluster=cluster,
										service=service,
										desiredCount=desired_count
										#task_definition=
										)
	return service

def create_cluster(name=None):
	cluster = ecs_client.create_cluster(clusterName=name)
	return cluster

def delete_cluster(cluster):
	response = ecs_client.delete_cluster(cluster=cluster)
	return response

def list_services(cluster):
	services = ecs_client.list_services(cluster=cluster)
	return services['serviceArns']

def describe_services(cluster):
	#services = [service.split('/')[1] for service in list_services(cluster)]
	services = list_services(cluster)
	descriptions = ecs_client.describe_services(cluster=cluster, services=services)
	return descriptions['services']

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

def set_count_services_zero(cluster=None, services=None):
	for service in services:
		update_service(cluster=cluster, service=service, desired_count=0, task_definition=None, deployment_conf=None)

def clearup_cluster(cluster):
	services = list_services(cluster)
	set_count_services_zero(cluster, services)
	time.sleep(2)
	stop_tasks(cluster)
	time.sleep(2)
	

cluster = 'xmpp_component_cluster'
#services = list_services(cluster)
#print(services)
#tasks = list_tasks(cluster)
#print(tasks)
#services_description = describe_services(cluster)
#print(services_description[0].keys())
#set_count_services_zero(cluster, services)
#tasks_descriptions = describe_tasks(cluster)
#print(tasks_descriptions)
response = stop_tasks(cluster)
print(response)

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


def get_task_role_arn(task_role):
	task_role_arn = task_role['arn'] # not sure if this really works
	return task_role_arn

task_role_arn = 'arn:aws:iam::876701361933:role/xmpp_component_task_role'

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

def log_metric(metric_name=None, metric_value=None, namespace=None):
	response = cloudwatch_client.put_metric_data(
	#MetricName=metric_name,
	Namespace=namespace,
	#Statistic='Maximum', # Statistic to apply to the alarm's associated metric
	MetricData=[
		{
			'MetricName': metric_name,
			#'Timestamp': date,
			'Value': metric_value
		}
	]
	#Dimensions=[{'Name': 'xmpp_component', 'Value': 'scaleup'}],
	#Period=60, # The period in seconds over which the statistic is applied: granularity? 
	#Unit='Milliseconds', # Not sure what should going in here...
	#EvaluationPeriods=3,
	#Threshold=50,
	#ComparisonOperator='GreaterThanOrEqualToThreshold'
	)
	return response 

def test_metric_alarm(namespace=None, metric_name=None, metric_values=None, alarm=None):
	for value in metric_values:
		log_metric(namespace=namespace, metric_name=metric_name, metric_value=value)
		print('logged {}'.format(value))
		time.sleep(1)
	cloudwatch_client.set_alarm_state(AlarmName=alarm,
									StateValue='OK',
									StateReason='Test finished, back to OK state.')

def list_clusters():
	clusters = ecs_client.list_clusters()
	return clusters['clusterArns']

#clusters = list_clusters()
#print(clusters)

def describe_clusters():
	clusters = list_clusters()
	details = ecs_client.describe_clusters(clusters=clusters)
	return details['clusters']

def describe_cluster(cluster_name):
	cluster = list(filter(lambda cluster: cluster_name in cluster, list_clusters()))
	details = ecs_client.describe_clusters(clusters=cluster)
	return details['clusters'][0]

#details = describe_clusters()
#print(details)

#details = describe_cluster('xmpp_component_cluster')
#print(details)

def list_roles():
	roles = iam_client.list_roles()['Roles']
	for role in roles:
		print(role['RoleName'], role['Arn'])


docker_login = open('docker-login.txt').read()


def create_instance_profile(name=None, path=None):
	profile = iam_client.create_instance_profile(InstanceProfileName='ec2InstanceProfileECS')
	return profile

def update_instance_profile():
	pass


def add_role2profile(role_name=None, profile_name=None):
	response = iam_client.add_role_to_instance_profile(InstanceProfileName='ec2InstanceProfileECS',
														RoleName='ec2InstanceRole')
	return response


def launch_ec2():
	image_id = get_most_recent_opt_AMI()['ImageId']
	instance = ec2_client.run_instances(#ryRun=True,
				ImageId=image_id,
				MinCount=1,
				MaxCount=1,
				KeyName='ecs_cluster',
				#SecurityGroups=[], This is for VPCs
				SecurityGroupIds=['testxmpp'],
				UserData=docker_login,
				InstanceType='t2.micro',
				#Placement={
					#'AvailabilityZone': 'eu-west-1',
					#'GroupName': 'xmpp_component_cluster',
					#'Tenancy': ,
					#'HostId': ,
					#'Affinity': 
				#},
				#KernelId='',
				#RamdiskId,
				#BlockDeviceMappings=[]
				Monitoring={
					'Enabled': True
				},
				#SubnetId=
				#DisableApiTerminator
				#InstanceInitiatedShutdownBehavior
				#PrivateIpAddress
				#ClientTocken
				#AdditionalInfo
				#NetworkInterfaces
				IamInstanceProfile={
					'Arn': 'arn:aws:iam::876701361933:instance-profile/ec2InstanceProfileECS'
					#'Name': 'XMPP-instance-profile'
				},
				#EbsOptimized
				)
	return instance

def create_group():
	group = ec2_client.create_security_group(DryRun=True,
											GroupName='ECS_Group',
											Description='Security group for instances running in a cluster.'
											)
	return group

def add_group_rule(group=None):
	response = ec2_client.authorize_security_group_ingress(DryRun=True,
															GroupName='ECS_Group',
															#SourceSecurityGroupName
															#SourceSecurityGroupOwnerId
															#IpProtocol
															#FromPort
															#ToPort
															#CidrIp
															IpPermissions={
																			#'IpProtocol'
																			#FromPort
																			#ToPort
																			#UserIdGroupPairs
															}
															)
	return response

def register_ec2():
	response = ecs_client.register_container_instance(cluster='xmpp_component_cluster',
														#containerInstanceArn=
														#attributes=[{
														#			'name': 'service',
														#			'value': 'xmpp_component'
														#		}
														#	]
														)
	return response


def attach_policy(name=None, policy_arn=None):
	response = iam_client.attach_role_policy(RoleName=name,
							PolicyArn=policy_arn)
	return response


def find_images():
	images = ec2_client.describe_images(Filters=[
											{
												'Name': 'architecture', 
												'Values': ['x86_64']
											},
											{
												'Name': 'owner-id',
												'Values': ['591542846629']
											},
											{
												'Name': 'virtualization-type',
												'Values': ['hvm']
											},
											{
												'Name': 'root-device-type',
												'Values': ['ebs']
											}
										])
	return images

def iso2map(iso):
	'''
	Parses a date in ISO format, e.g. 2015-10-28T21:08:08.000Z,
	and returns a map object with year, month converted into int
	types. The values must be unpacked. 
	'''
	year_month_day_str_list = iso[:10].split('-')
	return map(int, year_month_day_str_list)


def get_dt(image):
	if 'preview' not in image['Name']:
		date = image['CreationDate']
		year, month, day = iso2map(date)
		dt = datetime.datetime(year, month, day)
		return dt

def get_most_recent_opt_AMI():
	images = (image for image in find_images()['Images'] if 'preview' not in image['Name'])
	maxim = max(images, key=lambda x: get_dt(x))
	return maxim


def create_zip(file):
	zip_file = None
	filename, extension = os.path.splitext(file)
	zip_file_name = filename+'.zip'
	buffer = BytesIO()
	with ZipFile(buffer, 'w') as zip_file:
		zip_file.write(file)
	buffer.seek(0)
	return bytes(buffer.getbuffer())


def create_lambda(name=None, runtime='python2.7', role=None, handler=None, code_file=None, description=None):
	zipfile = create_zip(code_file)
	#zipfile = ZipFile(zip_file_name)
	function = lambda_client.create_function(FunctionName=name,
												Runtime=runtime,
												Role=role,
												Handler=handler,
												Code={'ZipFile': zipfile},
												Description=description
												)
	return function

def delete_lambda(name=None):
	response = lambda_client.delete_function(FunctionName=name)
	return response

def update_lambda(name=None, code_file=None):
	zipfile = create_zip(code_file)
	function = lambda_client.update_function_code(FunctionName=name,
													ZipFile=zipfile)
	return function

def list_lambdas():
	lambdas = lambda_client.list_functions()
	return lambdas['Functions']


def list_ec2():
	pass #with ecs_resource = boto3.resource('ec2')

#list roles; list instance profiles; 

def describe_service(service_name=None, cluster=None):
	services = ecs_client.describe_services(cluster=cluster,
							services=[service_name])['services'][0]
	return services

def list_task_definitions():
	tasks = ecs_client.list_task_definitions()['taskDefinitionArns']
	return tasks


def describe_task_definition(family=None, revision=None):
	response = ecs_client.describe_task_definition(taskDefinition=family)['taskDefinition']
	return response 


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

	#service = describe_service(cluster='xmpp_component_cluster', service_name='xmpp_component_service')
	#print(service['desiredCount'])


	high_values = (random.randint(51,100) for i in range(65))
	low_values = (random.randint(0,49) for i in range(65))
	#test_metric_alarm(namespace='xmpp_component', metric_name='queue_size', metric_values=high_values, alarm='xmpp_component_queue_size_increase')