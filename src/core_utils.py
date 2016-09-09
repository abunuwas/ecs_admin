def filter_arg(value, filter_params):
	if type(value) is dict:
		values = filter_args(value, filter_params)
		print(values)
	return all(value != param for param in filter_params)

def filter_args(args, filter_params=None):
	if filter_params is None:
		filter_params = ['', None]
	return dict((key, value) for key, value in args.items() if filter_arg(value, filter_params))

def filter_args_deep(args, filter_params=None):
	filtered_dict = {}
	for key, value in args.items():
		if type(value) == dict:
			print(filter_args(value))
			args.update(filter_args(value, filter_params))
		else:
			pass
	return filter_args(args, filter_params)


deep_dict = {
			'cluster': 'a_cluster',
			'serviceName': 'service_name',
			'taskDefinition': 'task_definition',
			'desiredCount': 'desired_count',
			'clientToken': None,
			'deploymentConfiguration': {
				'maximumPercent': None,
				'minimumHealthyPercent': 'min_health'
			}	
}

def make_tuple(value):
	if type(value) is not dict:
		return value
	else:
		value = value.items()
	return make_tuple(value)


#for element in make_tuple(deep_dict):
#	print(element)

import copy

def deep_filter(dic):
	new_dict = filter_args(dic)
	if all(type(value) is not dict for value in new_dict.values()):
		return new_dict
	else: 
		raise Exception('we still need to parse!')
	'''
	new_dict = dict((key, value) for key, value in dic)
	if key is None:
		for key, value in dic:
			if type(value) is dict:
				asdf(value, key=key)
			else: 
				new_dict[key] = value
	else:
		for key, value in dic[key]:
			if type(value) is dict:
				asdf(value, key=key)
			else: 
				new_dict[key] = value		
	'''

new_dict = deep_filter(deep_dict)
for element in new_dict.items():
	print(element)

#args = {'memory': 100, 'cpu': 200, 'image': 'image', 'container': None, 'definition': ''}
#filter_params = [None, '']
#filtered = filter_args(args, filter_params)
#print(filtered) -> {'memory': 100, 'cpu': 200, 'image': 'image'}


