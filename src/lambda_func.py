import boto3
lambda_client = boto3.client('lambda')
#from iam import list_roles

class Lambda:
    pass 

def create_zip(file):
    zip_file = None
    filename, extension = os.path.splitext(file)
    zip_file_name = filename+'.zip'
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as zip_file:
        zip_file.write(file)
    buffer.seek(0)
    return bytes(buffer.getbuffer())

def create_lambda(name=None, runtime='python2.7', role_arn=None, handler=None, code_file=None, description=None):
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

def add_permission(function_name, action, principal):
    request = lambda_client.add_permission(FunctionName=function_name,
                                StatementId='aStatement',
                                Action=action,
                                Principal=principal)
    return request 

def add_permissions(function_name, permissions):
    '''
    :permissions type: list(tuple)
    :permissions parameter: A list of tuples comprising the principal
        and the action which this principal is allowed to take on the
        lambda function. 
    '''
    for permission in permissions:
        action, principal = permission
        lambda_client.add_permission(function_name, action, principal)

def delete_lambda(name=None):
    response = lambda_client.delete_function(FunctionName=name)
    return response

