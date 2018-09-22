from flask import Flask, request, jsonify, render_template, render_template_string
from werkzeug.utils import secure_filename
# from aws_xray_sdk.core import xray_recorder
# from aws_xray_sdk.ext.flask.middleware import XRayMiddleware
from random import randint
import json
import yaml

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = 'secret'
app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
app.config['STATIC_FOLDER'] = None
app.config['UPLOAD_FOLDER'] = '/tmp'

# xray_recorder.configure(service='Orrible Flask App', dynamic_naming='*mysite.com*')
# XRayMiddleware(app, xray_recorder)


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

@app.route('/yaml', methods = ['POST', 'GET'])
def yaml_hammer():
    if request.method == 'GET':
        return render_template('yaml_test.html')
    if request.method == "POST":
        f = request.files['file']
        rand = randint(1, 100)
        fname = secure_filename(f.filename)
        fname = str(rand) + fname  # change file name
        file_path = app.config['UPLOAD_FOLDER'] + fname
        f.save(file_path)  # save file locally

        with open(file_path, 'r') as yfile:
            y = yfile.read()

        ydata = yaml.load(y)

    return render_template('view.html', name = json.dumps(ydata))

