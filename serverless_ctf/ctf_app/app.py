from chalice import Chalice, BadRequestError, UnauthorizedError
import boto3
from time import sleep
from io import BytesIO
from docx import Document
from base64 import b64encode
import jwt
import cgi
from boto3.dynamodb.conditions import Attr
from uuid import uuid4
import hashlib


app = Chalice(app_name='ctf_app')
s3 = boto3.client('s3')

HMAC_PASSWORD = '' #Haha, this would have been too easy

def get_user_for_event(event_key):
    dynamo = boto3.resource('dynamodb', region_name='us-east-1')
    try:
        print(event_key)
        table = dynamo.Table('ctf_resumes')
        resp = table.get_item(Key={'filename': event_key})
        if resp.has_key('Item'):
            print resp['Item']
            return resp['Item']['email']
    except Exception as e:
        app.log.error(e)
        return None

def _get_parts():
    rfile = BytesIO(app.current_request.raw_body)
    content_type = app.current_request.headers['content-type']
    _, parameters = cgi.parse_header(content_type)
    parameters['boundary'] = parameters['boundary'].encode('utf-8')
    parsed = cgi.parse_multipart(rfile, parameters)
    return parsed

def is_valid_jwt(token):
    dynamo = boto3.resource('dynamodb', region_name='us-east-1')
    if token.has_key('username'):
        table = dynamo.Table('ctf_users')
        resp = table.scan(Select='ALL_ATTRIBUTES', FilterExpression=Attr('username').eq(token.get('username')))
        if resp.has_key('Items'):
            return resp['Items']
        else:
            raise Exception("Unable to verify user role")
    else:
        raise Exception("Token doesnt have required value")

@app.route('/login', methods = ['POST'], cors = True)
def login():
    try:
        dynamo = boto3.resource('dynamodb', region_name='us-east-1')
        jbody = app.current_request.json_body
        if 'email' in jbody and 'password' in jbody:
            user_table = dynamo.Table('ctf_users')
            resp = user_table.get_item(Key={'email': jbody['email']})
            if 'Item' in resp:
                if resp['Item']['password'] == hashlib.md5(jbody['password']).hexdigest():
                    token = jwt.encode({'username': resp['Item']['username']}, key=HMAC_PASSWORD,
                                       algorithm='HS256')
                    return {'success': True, 'token': token}
                else:
                    return UnauthorizedError('Unable to verify user credentials')
            else:
                return UnauthorizedError('Unable to find user')
        else:
            return BadRequestError('Mandatory fields email and password not present')
    except Exception as e:
        return BadRequestError(e)


@app.route('/upload_file', methods = ['POST'], content_types=['multipart/form-data'], cors = True)
def upload_resume():
    try:
        dynamo = boto3.resource('dynamodb', region_name='us-east-1')
        hello = dict(app.current_request.headers)
        if hello.has_key('authorization'):
            decoded = jwt.decode(str(hello['authorization']), algorithms=['HS256'], verify=False)
            details = is_valid_jwt(decoded)
        else:
            return UnauthorizedError('No Authorization Header Found')

        rfile = BytesIO(app.current_request.raw_body)
        content_type = app.current_request.headers['content-type']
        _, parameters = cgi.parse_header(content_type)
        parameters['boundary'] = parameters['boundary'].encode('utf-8')
        files = cgi.parse_multipart(rfile, parameters)

        try:
            for k, v in files.items():
                file_key = '{}-{}.docx'.format(details[0]['username'], str(uuid4()))
                docx_stream = BytesIO(v[0])
                docx_stream.seek(0)
                s3.upload_fileobj(docx_stream, 'sls-ctf-resumes', file_key)

            table = dynamo.Table('ctf_resumes')
            table.put_item(
                Item={
                    'filename': file_key,
                    'email': details[0]['email'],
                    'username': details[0]['username']
                }
            )
            return {'uploaded': True}
        except Exception as s3_e:
            return BadRequestError("S3 Error: {}".format(s3_e))
    except Exception as e:
        return BadRequestError(e)


@app.route('/create_user', methods = ['PUT'], cors = True)
def create_user():
    try:
        dynamo = boto3.resource('dynamodb', region_name='us-east-1')
        jbody = dict(app.current_request.json_body)
        if jbody.has_key('email') and jbody.has_key('username') and jbody.has_key(
                'password') and jbody.has_key('repeat_password'):
            if jbody['password'] == jbody['repeat_password']:
                print jbody
                user_table = dynamo.Table('ctf_users')
                response = user_table.put_item(
                    Item = {
                        'email': jbody['email'],
                        'username': jbody['username'],
                        'password': hashlib.md5(jbody['password']).hexdigest()
                    }
                )
                print response
                return {'success': True}
            else:
                return BadRequestError('Passwords do not match')
        else:
            return BadRequestError("You need to have the email, username, password and repeat_password fields")
    except Exception as e:
        return BadRequestError(e)


@app.on_s3_event(bucket='sls-ctf-resumes', events=['s3:ObjectCreated:*'])
def uploaded_resume_handler(event):
    dynamo = boto3.resource('dynamodb', region_name='us-east-1')
    print("Received event for bucket: {}, key: {}".format(event.bucket, event.key))
    file_name = event.key
    s3 = boto3.resource('s3')
    try:
        email = get_user_for_event(file_name)
        if email:
            docfile = s3.Object('sls-ctf-resumes', file_name)
            docbody = BytesIO(docfile.get()['Body'].read())
            docobj = Document(docbody)
            all_paras = ""
            for para in docobj.paragraphs:
                all_paras += para.text
            all_paras = b64encode(all_paras)
            print(all_paras)
            try:
                cv_table = dynamo.Table('ctf_resumes')
                response = cv_table.get_item(Key={'filename': file_name})
                item = response['Item']
                item['file_content'] = all_paras
                cv_table.put_item(Item=item)
                app.log.debug(response)
            except Exception as e:
                print(e.message)

        else:
            raise Exception("Unable to find email")

    except Exception as e:
        print(e)


