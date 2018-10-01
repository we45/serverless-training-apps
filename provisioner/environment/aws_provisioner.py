"""we45 Training Provisioner for AWS

Usage:
  aws_provisioner.py iam create_policy [--policy_type=<policytype>]
  aws_provisioner.py iam create_users <seed> [--num-users=<numuser>]
  aws_provisioner.py iam export_user_csv --seed=<seed>
  aws_provisioner.py iam delete_users [--seed=<seed>] [--username=<username>]

Options:
  -h --help     Show this screen.
  --version     Show version.
  --gen-data=<val>    Generates 10 dummy entries in the payment-cards db
  --policy_type=<policytype>    Specify policy type, default is limited
  --num-users=<numuser> Specify number of users. Default is 1
  --seed=<seed> Seed for user location
  --username=<username> Username for User deletes
"""


import boto3
from docopt import docopt
import sys
import shelve
from huepy import *
from faker import Faker
import json
from random import randint, choice
import redis

iam = boto3.client('iam')
dynamo = boto3.client('dynamodb')
s3 = boto3.client('s3')
db = redis.StrictRedis(host='localhost', port=6379, db=0)
ACCOUNT_ID = '358174707935'
fake = Faker()
pass_chars = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#
def gen_random_password():
    password = ""
    for c in range(10):
        password += choice(pass_chars)
    return password

def gen_users(seed):
    username = "{}-user-{}".format(seed, randint(0, 999999))
    try:
        response = iam.create_user(
            UserName=username,
            # PermissionsBoundary=json.loads(db.get('limited_iam_policy'))['arn']
        )
        user_dict = {username: {'user_id': response['User']['UserId'], 'arn': response['User']['Arn']}}
        password = gen_random_password()
        profile_response = iam.create_login_profile(
            UserName=username,
            Password=password,
            PasswordResetRequired=False
        )
        user_policy = iam.attach_user_policy(
            UserName = username,
            PolicyArn = 'arn:aws:iam::358174707935:policy/TraineePolicyLimited'
        )

        access_key = iam.create_access_key(
            UserName = username
        )
        if 'AccessKey' in access_key:
            user_dict[username]['access_key'] = access_key['AccessKey']['AccessKeyId']
            user_dict[username]['secret'] = access_key['AccessKey']['SecretAccessKey']

        user_dict[username]['password'] = password
        print good("{} generated in IAM with Management console access".format(username))
        return user_dict
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))

def generate_sls_training_users(seed, num = 1):
    if num > 1:
        for i in range(0,num):
            user_dict = gen_users(seed)
            db.lpush('limited_iam_users', json.dumps(user_dict))
    elif num == 1:
        user_dict = gen_users(seed)
        db.lpush('limited_iam_users', json.dumps(user_dict))

    else:
        print bad('Unrecognized number of users. Exiting...')
        sys.exit(1)

def delete_users_by_seed(seed):
    user_length = db.llen('limited_iam_users')
    if user_length > 0:
        for i in range(0, user_length):
            user = json.loads(db.lindex('limited_iam_users',i))
            username = user.keys()[0]
            if username.startswith(seed):
                try:

                    login_pro = iam.delete_login_profile(UserName=username)
                    remove_keys = iam.delete_access_key(UserName = username, AccessKeyId = user[username]['access_key'])
                    policy_remove = iam.detach_user_policy(UserName=username,
                                                           PolicyArn='arn:aws:iam::358174707935:policy/TraineePolicyLimited')

                    response = iam.delete_user(UserName = username)
                    db.lrem('limited_iam_users', i, json.dumps(user))
                    print good("Deleted user with username: {}".format(username))
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))

    print good("Successfully removed all users with seed: {}".format(seed))


def delete_users_by_username(user_name):
    user_length = db.llen('limited_iam_users')
    if user_length > 0:
        for i in range(0, user_length):
            user = json.loads(db.lindex('limited_iam_users', i))
            username = user.keys()[0]
            if user_name == username:
                try:
                    iam.delete_login_profile(UserName = username)
                    iam.delete_access_key(UserName = username, AccessKeyId = user[username]['access_key'])
                    iam.detach_user_policy(UserName=username,
                                                           PolicyArn='arn:aws:iam::358174707935:policy/TraineePolicyLimited')
                    iam.delete_user(UserName = username)
                    db.lrem('limited_iam_users', i, json.dumps(user))
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
    print good("Successfully user with username: {}".format(username))


def gen_csv_file(user_list):
    with open('users.csv','w') as csvfile:
        for user in user_list:
            main_key = user.keys()[0]
            # print user.keys()[0]['arn']
            csvfile.write('{},{},{},{},{},{}\n'.format(main_key, user[main_key]['arn'],
                                                 user[main_key]['password'],
                                                 user[main_key]['user_id'],
                                                 user[main_key]['access_key'],
                                                 user[main_key]['secret']))

    print good('Successfully written users list to csv file')



def export_users_to_csv(seed = None):
    export_list = []
    if seed:
        user_length = db.llen('limited_iam_users')
        if user_length > 0:
            for i in range(0, user_length):
                user = json.loads(db.lindex('limited_iam_users', i))
                print user
                if user.keys()[0].startswith(seed):
                    export_list.append(user)
        gen_csv_file(export_list)
    else:
        user_length = db.llen('limited_iam_users')
        if user_length > 0:
            for i in range(0, user_length):
                user = json.loads(db.lindex('limited_iam_users', i))
                export_list.append(user)
        gen_csv_file(export_list)





if __name__ == '__main__':
    arguments = docopt(__doc__, version='we45 AWS Provisioner 1.0')
    if arguments['iam']:
        if arguments['create_users']:
            if arguments['<seed>']:
                print good("users with {} will be created".format(arguments['<seed>']))
                generate_sls_training_users(arguments['<seed>'],num = int(arguments['--num-users']))
            else:
                print bad("you need to specify a user seed")
        elif arguments['delete_users']:
            if arguments['--seed']:
                delete_users_by_seed(arguments['--seed'])
            elif arguments['--username']:
                delete_users_by_username(arguments['--username'])
            else:
                print bad("Can't recognize input. Please provide an appropriate value")
        elif arguments['export_user_csv']:
            if arguments['--seed']:
                export_users_to_csv(arguments['--seed'])
            else:
                print bad('No seed given. Exiting...')
        else:
            print bad("cannot understand these options. Please try again")
            sys.exit(1)
    else:
        print bad('Unable to understand given options.Exiting now...')
        sys.exit(1)