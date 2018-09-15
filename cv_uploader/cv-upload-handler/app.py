from chalice import Chalice
import boto3
from base64 import b64encode
from docx import Document
from io import BytesIO

app = Chalice(app_name='chalice-cv-event-handler')


@app.on_s3_event(bucket='cv-uploader', events=['s3:ObjectCreated:*'])
def cv_event_handler(event):
    print("Received event for bucket: {}, key: {}".format(event.bucket, event.key))
    s3 = boto3.resource('s3')
    try:
        docfile = s3.Object('cv-uploader', event.key)
        docbody = BytesIO(docfile.get()['Body'].read())
        print(docbody)
        docobj = Document(docbody)
        all_paras = ""
        for para in docobj.paragraphs:
            all_paras += para.text
        all_paras = b64encode(all_paras)
        print(all_paras)
        try:
            dynamo = boto3.resource('dynamodb')
            cv_table = dynamo.Table('uploaded-cv')
            response = cv_table.put_item(Item = {
                'cv_id': event.key,
                'body': all_paras
            })
            app.log.debug(response)
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)

@app.route('/fetch_dynamo_results', methods = ['GET'], cors = True)
def get_dynamo_data():
    dynamo = boto3.resource('dynamodb')
    cv_table = dynamo.Table('uploaded-cv')
    response = cv_table.scan(Limit = 5)
    return response
