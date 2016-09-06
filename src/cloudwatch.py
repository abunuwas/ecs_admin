import boto3
cloudwatch_client = boto3.client('cloudwatch')

def list_metrics():
	metrics = cloudwatch_client.list_metrics()
	return metrics['Metrics']

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

'''
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
'''

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

def set_state_alarm():
	pass 
