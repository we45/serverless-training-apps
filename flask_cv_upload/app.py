from flask import Flask, request, jsonify, render_template, render_template_string
import boto3
from faker import Faker
from werkzeug.utils import secure_filename
import os
from io import BytesIO

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = 'secret'
app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
app.config['STATIC_FOLDER'] = None
app.config['UPLOAD_FOLDER'] = '/tmp'

fake = Faker()

dynamo = boto3.client('dynamodb')
s3 = boto3.client('s3')

@app.route("/create_table", methods = ['GET'])
def create_table():
    try:
        response = dynamo.create_table(
            AttributeDefinitions = [
                {
                    'AttributeName': 'email',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'username',
                    'AttributeType': 'S'
                }
            ],
            KeySchema = [
                {
                    'AttributeName': 'email',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'username',
                    'KeyType': 'RANGE'
                }
            ],
            ProvisionedThroughput = {
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            },
            TableName = 'dynamo-user'
        )
        return jsonify(response),200
    except dynamo.exceptions.ResourceInUseException:
        return jsonify({'error': 'table has been created already. Moving on...'}),400

@app.route("/echo_service", methods = ["POST"])
def echo_service():
    body = request.json
    if 'search_term' in body:
        template = '''<html>
            <head>
            <title>Confirmation Page</title>
            </head>
            <body>
            <h1>Is this what you searched for?/h1>
            <h3>%s</h3>
            </body>
            </html>
            ''' % body['search_term']
        return render_template_string(template, dir=dir, help=help, locals=locals),200
    else:
        return jsonify({'error': "Unable to find the right search_term"}),404

# @app.route("/upload_cv", methods = ['GET', 'POST'])
# def upload_cv():
#     if request.method == 'GET':
#         return render_template('upload_cv.html')
#     elif request.method == 'POST':
#         if "user_file" not in request.files:
#             return jsonify({'error': 'no user_file in request'}),400
#
#         file = request.files['user_file']
#
#         if not file.filename.endswith('docx'):
#             return jsonify({'error': 'please upload docx files only'}),400
#
#         file_io = BytesIO(file.read())
#         file_io.seek(0)
#
#         try:
#             fake_filename = "{}-{}.docx".format(fake.first_name(), fake.user_name())
#             s3.upload_fileobj(file_io, 'cv-uploader', fake_filename)
#             return jsonify({'success': "File Uploaded as {}".format(fake_filename)})
#         except Exception as e:
#             print(e)
#             return e