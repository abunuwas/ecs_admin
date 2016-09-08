import boto3
sns_client = boto3.client('sns')

class SNS:
	pass 

def create_sns_topic(name=None):
	topic = sns_client.create_topic(Name=name)
	return topic['TopicArn']

def subscribe_sns_topic(arn=None, protocol=None, endpoint=None):
	subscription = sns_client.subscribe(TopicArn=arn,
										Protocol=protocol,
										Endpoint=endpoint)
	return subscription['SubscriptionArn']

def create_notification(name=None, protocol=None, endpoint=None):
	topic = create_sns_topic(name)
	subscription = subscribe_sns_topic(arn=topic, protocol=protocol, endpoint=endpoint)
	return topic, subscription

def delete_sns_topic(arn=None):
	response = sns_client.delete_topic(TopicArn=arn)
	return response
