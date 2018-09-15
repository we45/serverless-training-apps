from chalice import Chalice, BadRequestError, UnauthorizedError
import shelve
import jwt

app = Chalice(app_name='jwt-claim-service')

HMAC_PASSWORD = 'secret'
d = shelve.open('users')

@app.route('/init_users', methods = ['GET'])
def initialize_users():
    try:
        d['john.smith@widget.co'] = {'username': 'jsmith', 'role': 'user', 'password': 'helloworld'}
        d['robert.hardy@widget.co'] = {'username': 'rhardy', 'role': 'admin', 'password': 'hellouniverse'}
        return {'success': 'users created'}
    except Exception as e:
        raise BadRequestError(e)

@app.route('/login', methods = ['POST'])
def authenticate():
    try:
        request = app.current_request.json_body
        print request['email']
        if request.has_key('email') and request.has_key('password'):
            if d.has_key(request['email']):
                if request['password'] == d[request['email']]['password']:
                    token = jwt.encode({'username': d[request['email']]['username']}, key=HMAC_PASSWORD, algorithm='HS256')
                    return { 'success': 'authenticated', 'token': token }
                else:
                    raise UnauthorizedError('Invalid credentials')
            else:
                raise BadRequestError("No such user")
        else:
            raise BadRequestError('No email or password value in request')
    except Exception as e:
        raise BadRequestError(e)

@app.route('/protected', methods= ['GET'])
def protected_area():
    hello = dict(app.current_request.headers)
    if hello.has_key('authorization'):
        token = jwt.decode(hello['authorization'], key=HMAC_PASSWORD, algorithm = "HS256")
        for key in d.keys():
            if d[key]['username'] == token['username']:
                if d[key]['role'] == 'admin':
                    return {'success': 'You, {}, are an Administrator'.format(d[key]['username'])}
                elif d[key]['role'] == 'user':
                    return {'success! but a little less': 'You, {}, are an ordinary user'.format(d[key]['username'])}
                else:
                    return BadRequestError("I don't recognize this role")
    else:
        return BadRequestError("There's no Auth Token in your request. Ta ta!")

@app.route('/list_users', methods = ['GET'])
def list_users():
    all_users = {}
    for key in d.keys():
        all_users[key] = key['username']
    return all_users


@app.route('/add_user/{email}', methods = ['PUT'])
def add_user(email):
    try:
        request = app.current_request.json_body
        if request.has_key('username') and request.has_key('role') and request.has_key('password'):
            d[email] = {'username': request['username'], 'password': request['password'], 'role': request['role']}
            return {'success': 'user with {} created'.format(email)}
        else:
            raise BadRequestError('Please submit all the required fields')
    except Exception as e:
        raise BadRequestError(e)


@app.route('/delete_user/{email}', methods = ['DELETE'])
def delete_user(email):
    try:
        del d[email]
        return {'success': 'user with email {} deleted'.format(email)}
    except Exception as e:
        raise BadRequestError(e)

