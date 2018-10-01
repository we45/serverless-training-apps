'''
AWS Secrets Manager Demo
Usage:
  secrets_example.py create <secretname> <secret_string>
  secrets_example.py (get|describe) [--name=<secretname>] [--secret_arn=<arn>]


Options:
  -h --help     Show this screen.
  --version     Show version.
  --name=<secretname>   gets or describes secret by secret name provided
  --secret_arn=<arn>    gets or describes secret by secret arn provided
'''
import boto3
from huepy import *
from docopt import docopt

secrets = boto3.client('secretsmanager')

def create_new_secret(name, secret_str):
    try:
        secret = password = secrets.create_secret(Name = name,
                                           SecretString = secret_str)
        print good("Successfully added '{}' to AWS Secrets".format(name))
        print good(secret)
    except Exception as e:
        print bad(e)

def describe_secret(secret_name = None, secret_arn = None):
    print good("Describing Secret...")
    try:
        if secret_name:
            described = secrets.describe_secret(SecretId = secret_name)
        elif secret_arn:
            described = secrets.describe_secret(SecretId=secret_arn)
        else:
            print bad('Cant recognize input. Bye...')
        print good(described)
    except Exception as e:
        print bad(e)

def get_secret_value(secret_name = None, secret_arn = None):
    print good("Getting Secret Value...")
    try:
        if secret_name:
            value = secrets.get_secret_value(SecretId = secret_name)
        elif secret_arn:
            value = secrets.get_secret_value(SecretId=secret_arn)
        else:
            print bad('Cant recognize input. Bye...')
        print good(value)
    except Exception as e:
        print bad(e)

if __name__ == '__main__':
    arguments = docopt(__doc__, version='we45 AWS Secrets Demo v1')
    # print arguments
    if arguments['create']:
        if arguments['<secret_string>'] and arguments['<secretname>']:
            create_new_secret(arguments['<secretname>'], arguments['<secret_string>'])
        else:
            print bad("You need to provide the secretname and string params")
    elif arguments['get']:
        if arguments['--name']:
            get_secret_value(secret_name=arguments['--name'])
        elif arguments['--secret_arn']:
            get_secret_value(secret_arn=arguments['--secret_arn'])
        else:
            print bad("Unrecognized option. Bye!")
    elif arguments['describe']:
        if arguments['--name']:
            describe_secret(secret_name=arguments['--name'])
        elif arguments['--secret_arn']:
            describe_secret(secret_arn=arguments['--secret_arn'])
        else:
            print bad("Unrecognized option. Bye!")







