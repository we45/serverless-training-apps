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

#aws_provisioner.py all
#  aws_provisioner.py s3
#  aws_provisioner.py dynamo [--gen-data=<val>]


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


limited_user_permissions_policy = '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1537606288674",
      "Action": [
        "lambda:GetAccountSettings",
        "lambda:GetAlias",
        "lambda:GetEventSourceMapping",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:ListAliases",
        "lambda:ListEventSourceMappings",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "Stmt1537606394134",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification",
        "s3:GetBucketPolicy",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:ListBucketByTags"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "Stmt1537606522538",
      "Action": [
        "logs:DescribeDestinations",
        "logs:DescribeExportTasks",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:DescribeMetricFilters",
        "logs:DescribeResourcePolicies",
        "logs:DescribeSubscriptionFilters",
        "logs:DisassociateKmsKey",
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "logs:ListTagsLogGroup"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "Stmt1537606603891",
      "Action": [
        "dynamodb:DescribeBackup",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeGlobalTableSettings",
        "dynamodb:DescribeLimits",
        "dynamodb:DescribeReservedCapacity",
        "dynamodb:DescribeReservedCapacityOfferings",
        "dynamodb:DescribeStream",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:GetItem",
        "dynamodb:GetRecords",
        "dynamodb:ListBackups",
        "dynamodb:ListGlobalTables",
        "dynamodb:ListStreams",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
'''

# def create_s3_bucket():
#     try:
#         if db.has_key('cv_s3_bucket'):
#             print bad("No need to create a new s3 bucket. Already done")
#         else:
#             response = s3.create_bucket(Bucket = 'training-cv-uploader')
#             print good("Bucket: training-cv-uploader created, with message: {}".format(response))
#             db['cv_s3_bucket'] = {'name': 'training-cv-uploader', 'arn': 'arn:aws:s3:::{}'.format('training-cv-uploader')}
#
#         if db.has_key('ui_s3_bucket'):
#             print bad("There's already a UI S3 Bucket created")
#         else:
#             response = s3.create_bucket(Bucket = 'sls-training-ui')
#             print good("Bucket: sls-training-ui created, with message: {}".format(response))
#             db['ui_s3_bucket'] = {'name': 'sls-training-ui',
#                                   'arn': 'arn:aws:s3:::{}'.format('sls-training-ui')}
#     except Exception as e:
#         exc_type, exc_value, exc_traceback = sys.exc_info()
#         print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
#
# def gen_random_password():
#     password = ""
#     for c in range(10):
#         password += choice(pass_chars)
#     return password
#
# def create_dynamo_tables():
#     try:
#         if db.has_key('dynamo_cv_users'):
#             print bad("cv_users already in there. Not creating")
#         else:
#             print good("Creating cv_users table...")
#             response = dynamo.create_table(
#                 TableName = 'cv_users',
#                 KeySchema = [
#                     {
#                         'AttributeName': 'email',
#                         'KeyType': 'HASH'
#                     },
#                     {
#                         'AttributeName': 'username',
#                         'KeyType': 'RANGE'
#                     },
#                 ],
#                 AttributeDefinitions = [
#                     {
#                         'AttributeName': 'email',
#                         'AttributeType': 'S'
#                     },
#                     {
#                         'AttributeName': 'username',
#                         'AttributeType': 'S'
#                     },
#                 ],
#                 ProvisionedThroughput = {
#                     'ReadCapacityUnits': 100,
#                     'WriteCapacityUnits': 100
#                 }
#             )
#             print good("Table ARN: {}".format(response['TableDescription']['TableArn']))
#             db['dynamo_cv_users'] = {'name': 'cv_users', 'arn': response['TableDescription']['TableArn']}
#     except Exception as e:
#         exc_type, exc_value, exc_traceback = sys.exc_info()
#         print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
#
#     try:
#         if db.has_key('dynamo_uploaded_cvs'):
#             print bad("cv_data already in there. Not creating")
#         else:
#             print good("Creating cv_data table...")
#             response = dynamo.create_table(
#                 TableName='cv_data',
#                 KeySchema=[
#                     {
#                         'AttributeName': 'filename',
#                         'KeyType': 'HASH'
#                     },
#                     {
#                         'AttributeName': 'email',
#                         'KeyType': 'RANGE'
#                     },
#                 ],
#                 AttributeDefinitions=[
#                     {
#                         'AttributeName': 'filename',
#                         'AttributeType': 'S'
#                     },
#                     {
#                         'AttributeName': 'email',
#                         'AttributeType': 'S'
#                     },
#                 ],
#                 ProvisionedThroughput={
#                     'ReadCapacityUnits': 100,
#                     'WriteCapacityUnits': 100
#                 }
#             )
#             print good("Table ARN: {}".format(response['TableDescription']['TableArn']))
#             db['dynamo_uploaded_cvs'] = {'name': 'cv_data', 'arn': response['TableDescription']['TableArn']}
#
#     except Exception as e:
#         exc_type, exc_value, exc_traceback = sys.exc_info()
#         print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
#
#     try:
#         if db.has_key('dynamo_payment-cards'):
#             print bad("payment-cards already in there. Not creating")
#         else:
#             print good("Creating payment-cards table...")
#             response = dynamo.create_table(
#                 TableName='payment-cards',
#                 KeySchema=[
#                     {
#                         'AttributeName': 'card_number',
#                         'KeyType': 'HASH'
#                     },
#                 ],
#                 AttributeDefinitions=[
#                     {
#                         'AttributeName': 'card_number',
#                         'AttributeType': 'S'
#                     }
#                 ],
#                 ProvisionedThroughput={
#                     'ReadCapacityUnits': 100,
#                     'WriteCapacityUnits': 100
#                 }
#             )
#             print good("Table ARN: {}".format(response['TableDescription']['TableArn']))
#             db['dynamo_payment-cards'] = {'name': 'payment-cards', 'arn': response['TableDescription']['TableArn']}
#     except Exception as e:
#         exc_type, exc_value, exc_traceback = sys.exc_info()
#         print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
#
#
# def generate_dynamo_fake_data():
#     db = boto3.resource('dynamodb')
#     table = db.Table('payment-cards')
#     try:
#         for i in range(0,10):
#             table.put_item(
#                 Item = {
#                     'card_number': fake.credit_card_number(),
#                     'cardholder': fake.name(),
#                     'exp_date': int(fake.credit_card_expire(start="now", end="+10y", date_format="%m%y"))
#                 }
#             )
#         print good('Added 10 payment cards to the DB')
#     except Exception as e:
#         exc_type, exc_value, exc_traceback = sys.exc_info()
#         print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))
#
# def load_policy_iam(policy_type):
#     if policy_type == 'limited':
#         if db.get('limited_iam_policy'):
#             print bad("there's already a limited policy in place. Not creating...")
#         else:
#             try:
#                 response = iam.create_policy(
#                     PolicyName = 'TraineePolicyLimited',
#                     PolicyDocument = json.dumps(json.loads(limited_user_permissions_policy)),
#                     Description = 'This policy is meant for trainees to have view-only access to resources in AWS'
#                 )
#                 arn = response['Policy']['Arn']
#                 print good('Trainee policy generated with ARN: {}'.format(arn))
#                 db.set('limited_iam_policy', json.dumps({'name': 'TraineePolicyLimited', 'arn': arn}))
#             except Exception as e:
#                 exc_type, exc_value, exc_traceback = sys.exc_info()
#                 print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))

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
            PolicyArn = json.loads(db.get('limited_iam_policy'))['arn']
        )
        user_dict[username]['password'] = password
        print good("{} generated in IAM with Management console access".format(username))
        return user_dict
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print bad('Error: {0} {1}'.format(e, exc_traceback.tb_lineno))

def generate_sls_training_users(seed, num = 1):
    if num > 1:
        for i in range(0,num-1):
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
                    policy_remove = iam.detach_user_policy(UserName=username,
                                                           PolicyArn=json.loads(db.get('limited_iam_policy'))['arn'])
                    login_pro = iam.delete_login_profile(UserName=username)
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
                    policy_remove = iam.detach_user_policy(UserName=username,
                                                           PolicyArn=json.loads(db.get('limited_iam_policy'))['arn'])
                    login_pro = iam.delete_login_profile(UserName = username)
                    response = iam.delete_user(UserName = username)
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
            csvfile.write('{},{},{},{}\n'.format(main_key, user[main_key]['arn'], user[main_key]['password'], user[main_key]['user_id']))

    print good('Successfully written users list to csv file')



def export_users_to_csv(seed = None):
    export_list = []
    if seed:
        user_length = db.llen('limited_iam_users')
        if user_length > 0:
            for i in range(0, user_length):
                user = json.loads(db.lindex('limited_iam_users', i))
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
    # print(arguments)
    # if arguments['all']:
    #     create_s3_bucket()
    #     create_dynamo_tables()
    #     generate_dynamo_fake_data()
    # elif arguments['dynamo'] and arguments['--gen-data'] == False:
    #     create_dynamo_tables()
    # elif arguments['s3']:
    #     create_s3_bucket()
    # elif arguments['dynamo'] and arguments['--gen-data']:
    #     if arguments['--gen-data'] == 'with':
    #         create_dynamo_tables()
    #         generate_dynamo_fake_data()
    #     elif arguments['--gen-data'] == 'only':
    #         generate_dynamo_fake_data()
    #     else:
    #         print bad('Unable to understand given options.Exiting now...')
    #         sys.exit(1)
    if arguments['iam']:
        if arguments['create_policy']:
            load_policy_iam('limited')
        elif arguments['create_users']:
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