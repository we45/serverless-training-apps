from chalice import Chalice, BadRequestError, UnauthorizedError
import boto3
from base64 import b64encode
from docx import Document
from io import BytesIO
from time import sleep
import jwt
from boto3.dynamodb.conditions import Attr


app = Chalice(app_name='chalice-cv-event-handler')
dynamo = boto3.resource('dynamodb')
HMAC_PASSWORD = 'secret'
# xray_recorder.configure(context_missing='LOG_ERROR', plugins=('boto3'))
# patch_all()

def get_user_for_event(event_key):
    try:
        print(event_key)
        table = dynamo.Table('cv_data')
        resp = table.scan(Select='ALL_ATTRIBUTES', FilterExpression=Attr('filename').eq(event_key), Limit=1)
        print(resp)
        if resp.has_key('LastEvaluatedKey'):
            print resp['LastEvaluatedKey']
            return resp['LastEvaluatedKey']['email']
    except Exception as e:
        app.log.error(e)
        return None


# @xray_recorder.capture()
@app.on_s3_event(bucket='training-cv-uploader', events=['s3:ObjectCreated:*'])
def cv_event_handler(event):
    print("Received event for bucket: {}, key: {}".format(event.bucket, event.key))
    s3 = boto3.resource('s3')
    try:
        sleep(4)
        email = get_user_for_event(event.key)
        if email:
            docfile = s3.Object('training-cv-uploader', event.key)
            docbody = BytesIO(docfile.get()['Body'].read())
            docobj = Document(docbody)
            all_paras = ""
            for para in docobj.paragraphs:
                all_paras += para.text
            all_paras = b64encode(all_paras)
            print(all_paras)
            try:
                cv_table = dynamo.Table('cv_data')
                response = cv_table.update_item(Key = {'filename': event.key},
                                                UpdateExpression = "set file_content = :fc",
                                                ExpressionAttributeValues = {
                                                    ":fc": all_paras
                                                },
                                                ReturnValues = "UPDATED_NEW")
                app.log.debug(response)
            except Exception as e:
                print(e)

        else:
            raise Exception("Unable to find email")

    except Exception as e:
        print(e)


def is_valid_jwt(token):
    decoded = jwt.decode(token, key=HMAC_PASSWORD, algorithms=['HS256'])
    if decoded:
        if decoded.has_key('username'):
            table = dynamo.Table('cv_users')
            resp = table.scan(Select='ALL_ATTRIBUTES', FilterExpression=Attr('username').eq(decoded.get('username')))
            if resp.has_key('Items'):
                return resp['Items']['role']
            else:
                raise Exception("Unable to verify user role")
        else:
            raise Exception("Token doesnt have required value")
    else:
        raise Exception("Unable to decode JWT")


# @xray_recorder.capture()
@app.route('/protected', methods = ['GET'])
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

# @xray_recorder.capture()
@app.route('/delete_user/{email}', methods = ['DELETE'])
def delete_user(email):
    try:
        hello = dict(app.current_request.headers)
        if hello.has_key('authorization'):
            token = hello.get('authorization')
            if token == 'admin' or token == 'staff':
                table = dynamo.Table('cv_users')
                resp = table.delete_item(Key = {
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