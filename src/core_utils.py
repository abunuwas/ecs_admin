def filter_arg(value, filter_params):
	if type(value) is dict:
		values = filter_args(value, filter_params)
	return all(value != param for param in filter_params)

def filter_args(args, filter_params=None):
	if filter_params is None:
		filter_params = ['', {}, None]
	return dict((key, value) for key, value in args.items() if filter_arg(value, filter_params))

def make_tuples(dic, container, filter_params=None):
	## This function should probably be rewritten with
	## a closure pattern. 
	for key, value in dic.items():
		if type(value) is dict:
			new_container = [key]
			container.append(new_container)
			make_tuples(filter_args(value, filter_params), new_container)
		else:
			container.append(tuple((key, value)))
	return container

def make_dict(tuples, container):
	for _tuple in tuples:
		if type(_tuple) is tuple:
			key, value = _tuple
			container[key] = value
		elif type(_tuple) is list:
			key = _tuple[0]
			values = _tuple[1:]
			container[key] = {}
			new_container = container[key]
			make_dict(values, new_container)
	return container

def filter_args_deep(args, filter_params=None):
	tuples = make_tuples(args, container=[], filter_params=filter_params)
	filtered_args = make_dict(tuples, container={})
	return filter_args(filtered_args, filter_params)




deep_dict = {
			'cluster': 'a_cluster',
			'serviceName': 'service_name',
			'taskDefinition': 'task_definition',
			'desiredCount': 'desired_count',
			'clientToken': None,
			'deploymentConfiguration': {
				'maximumPercent': None,
				'minimumHealthyPercent': None
			}	
}



#filtered = filter_args_deep(deep_dict)
#print(filtered)

#args = {'memory': 100, 'cpu': 200, 'image': 'image', 'container': None, 'definition': ''}
#filter_params = [None, '']
#filtered = filter_args(args, filter_params)
#print(filtered) -> {'memory': 100, 'cpu': 200, 'image': 'image'}


