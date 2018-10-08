from chalice import Chalice, BadRequestError, UnauthorizedError
import boto3
from base64 import b64encode
# from docx import Document
from io import StringIO, BytesIO
from time import sleep
import jwt
from boto3.dynamodb.conditions import Attr
import cgi
from uuid import uuid4
from xml.dom.pulldom import START_ELEMENT, parse, parseString

app = Chalice(app_name='chalice-cv-event-handler')
dynamo = boto3.resource('dynamodb')
HMAC_PASSWORD = 'secret'
HMAC_PASSWORD_2 = '82a825e9-c919-4247-9638-4c8d20efba1e'


def get_user_for_event(event_key):
    try:
        print(event_key)
        table = dynamo.Table('cv_data')
        resp = table.get_item(Key={'filename': event_key})
        if resp.has_key('Item'):
            print resp['Item']
            return resp['Item']['email']
    except Exception as e:
        app.log.error(e)
        return None


@app.on_s3_event(bucket='training-cv-uploader', events=['s3:ObjectCreated:*'])
def cv_event_handler(event):
    print("Received event for bucket: {}, key: {}".format(event.bucket, event.key))
    file_name = event.key
    s3 = boto3.resource('s3')
    try:
        sleep(2)
        email = get_user_for_event(file_name)
        if email:
            docfile = s3.Object('training-cv-uploader', file_name)
            docbody = docfile.get()['Body'].read()
            doc = parseString(docbody)
            content = ''
            for event, node in doc:
                # print("Node", node.toxml())
                doc.expandNode(node)
                content = node.toxml()
                # print "content", content
            # docobj = Document(docbody)
            # all_paras = ""
            # for para in docobj.paragraphs:
            #     all_paras += para.text
            # all_paras = b64encode(all_paras)
            # print(all_paras)
            try:
                cv_table = dynamo.Table('cv_data')
                response = cv_table.get_item(Key={'filename': file_name})
                item = response['Item']
                item['file_content'] = b64encode(content)
                cv_table.put_item(Item=item)
                # response = cv_table.update_item(
                #     Key = {'filename': file_name},
                #     UpdateExpression = "set file_content = :fc",
                #     ExpressionAttributeValues = {":fc": b64encode(content)},
                #     ReturnValues = "UPDATED_NEW"
                # )
                app.log.debug(response)
            except Exception as e:
                print(e.message)

        else:
            raise Exception("Unable to find email")

    except Exception as e:
        print(e)


def is_valid_jwt(token):
    if token.has_key('username'):
        table = dynamo.Table('cv_users')
        resp = table.scan(Select='ALL_ATTRIBUTES', FilterExpression=Attr('username').eq(token.get('username')))
        print resp
        if resp.has_key('Items'):
            return resp['Items']
        else:
            raise Exception("Unable to verify user role")
    else:
        raise Exception("Token doesnt have required value")


@app.route('/protected', methods=['GET'], cors = True)
def protected_view():
    try:
        hello = dict(app.current_request.headers)
        if hello.has_key('authorization'):
            token = hello.get('authorization')
            if token == 'admin' or token == 'staff':
                return {'success': 'you are an administrator'}
            elif token == 'user':
                return {'less-success': 'You are just a user'}
            else:
                return BadRequestError('Unrecognized')
        else:
            return UnauthorizedError("No Authorization Token")
    except Exception as e:
        return BadRequestError(e)


@app.route('/delete_user/{email}', methods=['DELETE'], cors = True)
def delete_user(email):
    try:
        hello = dict(app.current_request.headers)
        if hello.has_key('authorization'):
            token = hello.get('authorization')
            if token == 'admin' or token == 'staff':
                table = dynamo.Table('cv_users')
                resp = table.delete_item(Key={
                    'email': email
                })
                if resp.has_key('Error'):
                    return BadRequestError("Unable to delete ")
                else:
                    return {'success': 'User with email: {} deleted'.format(email)}
            else:
                return UnauthorizedError('You are not allowed to execute this function')
        else:
            return UnauthorizedError("There's not token in your Request")
    except Exception as e:
        return BadRequestError(e)


def _get_parts():
    rfile = BytesIO(app.current_request.raw_body)
    content_type = app.current_request.headers['content-type']
    _, parameters = cgi.parse_header(content_type)
    parameters['boundary'] = parameters['boundary'].encode('utf-8')
    parsed = cgi.parse_multipart(rfile, parameters)
    return parsed


@app.route('/upload', methods=['POST'], content_types=['multipart/form-data'], cors = True)
def upload():
    try:
        hello = dict(app.current_request.headers)
        print hello['authorization']
        if hello.has_key('authorization'):
            decoded = jwt.decode(str(hello['authorization']), HMAC_PASSWORD_2, algorithms=['HS256'])
            print "decoded", decoded
            details = is_valid_jwt(decoded)
            # print "details",details[]
        s3 = boto3.client('s3')
        files = _get_parts()
        try:
            for k, v in files.items():
                file_key = '{}.xml'.format(str(uuid4()))
                s3.upload_fileobj(BytesIO(v[0]), 'training-cv-uploader', file_key)

            table = dynamo.Table('cv_data')
            table.put_item(
                Item={
                    'filename': file_key,
                    'email': details[0]['email'],
                    'username': details[0]['username']
                }
            )
            sleep(2)
            return {'uploaded': True}
        except Exception as e:
            print(e)
            return BadRequestError(e)
    except Exception as e:
        raise BadRequestError(e)


@app.route('/bad_dynamo_search', methods=['POST'], content_types=['application/json'], cors = True)
def bad_search():
    try:
        jbody = app.current_request.json_body
        if isinstance(jbody, dict):
            if jbody.has_key('db') and jbody.has_key('search_term') and jbody.has_key(
                    'search_operator') and jbody.has_key('search_field'):
                db = boto3.client('dynamodb')
                response = db.scan(TableName=jbody['db'], Select='ALL_ATTRIBUTES', ScanFilter={
                    jbody['search_field']: {"AttributeValueList": [{"S": jbody['search_term']}],
                                            "ComparisonOperator": jbody['search_operator']}
                })
                if response.has_key('Items'):
                    return {"search_results": response['Items']}
                else:
                    return {"search_results": None}
            else:
                return BadRequestError("All parameters are required to complete the search")
        else:
            return BadRequestError("Seems to be a wrong content type")
    except Exception as e:
        return BadRequestError(e.message)

@app.route("/whoami", methods = ['GET'], cors = True)
def whoami():
    hello = dict(app.current_request.headers)
    print hello['authorization']
    if hello.has_key('authorization'):
        try:
            decoded = jwt.decode(str(hello['authorization']), HMAC_PASSWORD_2, algorithms=['HS256'])
            # print "decoded", decoded
            details = is_valid_jwt(decoded)
            if details[0].has_key('role'):
                if details[0]['role'] == 'admin':
                    return {'success': {'user': details[0]['username'], 'email': details[0]['email'], 'role': details[0]['role']}}
                elif details[0]['role'] == 'user':
                    return {
                        'success': {'user': details[0]['username'], 'email': details[0]['email'], 'role': details[0]['role']}}
                else:
                    return BadRequestError('Not able to verify user')
            else:
                return BadRequestError('Unable to verify user, based on token')
        except Exception as e:
            return UnauthorizedError(e)
    else:
        return UnauthorizedError('No Token')