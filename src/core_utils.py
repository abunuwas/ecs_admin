def filter_arg(value, filter_params):
	return all(value != param for param in filter_params)

def filter_args(args, filter_params):
	return dict((key, value) for key, value in args.items() if filter_arg(value, filter_params))

#args = {'memory': 100, 'cpu': 200, 'image': 'image', 'container': None, 'definition': ''}
#filter_params = [None, '']
#filtered = filter_args(args, filter_params)
#print(filtered) -> {'memory': 100, 'cpu': 200, 'image': 'image'}


