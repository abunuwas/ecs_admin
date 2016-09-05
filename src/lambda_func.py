import boto3
lambda_client = boto3.client('lambda')


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

def list_lambdas():
	lambdas = lambda_client.list_functions()
	return lambdas['Functions']

def update_lambda(name=None, code_file=None):
	zipfile = create_zip(code_file)
	function = lambda_client.update_function_code(FunctionName=name,
													ZipFile=zipfile)
	return function

def delete_lambda(name=None):
	response = lambda_client.delete_function(FunctionName=name)
	return response