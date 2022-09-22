#!/bin/sh
''''which python3  >/dev/null 2>&1 && exec python3  "$0" "$@" # '''
''''which python  >/dev/null 2>&1 && exec python  "$0" "$@" # '''
''''exec echo "Error: No python module found in system" # '''




from sys import exit
from syslog import syslog
from os import environ
from time import sleep
import asyncio
from okta.client import Client as OktaClient
from okta import models
import boto3
from botocore.exceptions import ClientError
from ec2_metadata import ec2_metadata
def log(msg):
    syslog(f'Okta OpenVPN plugin: {msg}')


def failure(control, msg):
    log(f'auth failure: {msg}')

    f = open(control, 'w')
    f.write('0')
    f.close()

    exit(1)


def success(control, msg):
    log(f'auth success {msg}')

    f = open(control, 'w')
    f.write('1')
    f.close()

    exit(0)


def get_secret(control):

    secret_name = environ.get('aws_secret')

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=ec2_metadata.region
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        failure(control, e)

    else:
        log('Certificate received')
        return get_secret_value_response['SecretString']


def get_params():
    result = {}
    control = environ.get('control')
    username = environ.get('username')
    provider = environ.get('provider').strip().upper()
    password = environ.get('password').strip().lower()

    if password == 'push':
        pass
    elif password.startswith('otp'):
        pass_code = password[3:].replace(' ', '')
        if not pass_code.isnumeric():
            failure(control, f'{pass_code=} not number')
        result['pass_code'] = pass_code
        if provider == 'GOOGLE':
            result['provider'] = 'GOOGLE'
        result['factor_type'] = 'token:software:totp'
    else:
        failure(control, f'{password=} method not supported')

    result['control'] = control
    result['username'] = username
    return result


async def main(control, username, factor_type='push', provider='OKTA', pass_code='123456'):
    provider = models.FactorProvider(provider)
    amountOfTimesToLoop = 15  # 30 sec

    user, resp, err = await okta_client.get_user(username)
    assert user is not None, failure(control, f'{resp=}, {err=}')

    supported_factors, resp, err = await okta_client.list_factors(user.id)
    assert supported_factors is not None, failure(control, f'{resp=}, {err=}')

    factor = next(f for f in supported_factors if f.factor_type ==
                  factor_type and f.provider == provider)
    activated_factor, resp, err = await okta_client.verify_factor(user.id, factor.id, models.ActivateFactorRequest({'passCode': pass_code}))
    assert activated_factor is not None, failure(control, f'{resp=}, {err=}')

    result = activated_factor.factor_result
    while result == "WAITING" and amountOfTimesToLoop > 0:
        transaction = activated_factor.links['poll']['href'].split('/')[-1]
        log(result)
        sleep(2)
        activated_factor, resp, err = await okta_client.get_factor_transaction_status(user.id, factor.id, transaction)
        assert activated_factor is not None, failure(
            control, f'{resp=}, {err=}')
        result = activated_factor.factor_result
        amountOfTimesToLoop -= 1
    if result == "SUCCESS":
        success(control, f'{result=}')
    failure(control, f'{result=}')

if __name__ == '__main__':
    params = get_params()
    config = {
        'orgUrl': environ.get('okta_host') if environ.get('okta_host').startswith('https') else f'https://{environ.get("okta_host")}',
        'clientId': environ.get('okta_cid'),
        'authorizationMode': 'PrivateKey',
        'scopes': ['okta.factors.manage', 'okta.users.manage'],
        'privateKey': get_secret(params['control'])
    }
    okta_client = OktaClient(config)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(**params))
    failure(params['control'], 'EOF')
