import os
from base64 import b64encode
from nacl import encoding, public
from typing import Dict

import boto3
import json
import requests


def get_organization_public_key(github_token: str, organization_name: str) -> str:
    """
    Retrieve public key value for encrypting organization level secrets
    :return: The public key value
    """
    response = requests.get(
        url=f'https://api.github.com/orgs/{organization_name}/actions/secrets/public-key',
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )

    if response.status_code >= 300:
        raise Exception(f'ERROR: Failed to retrieve public key for secret encryption (HTTP status code {response.status_code})')

    response_dict = json.loads(response.content)
    return response_dict['key']


def get_repository_id(github_token: str, organization_name: str, repository_name: str) -> int:
    """
    Retrieve GitHub repository ID from repository name
    :param github_token:
    :param organization_name:
    :param repository_name:
    :return: Integer repository ID
    """
    print(f'Repository URL: https://api.github.com/repos/{organization_name}/{repository_name}')
    response_get_repository = requests.get(
        url=f'https://api.github.com/repos/{organization_name}/{repository_name}',
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )
    if response_get_repository.status_code >= 300:
        raise Exception(f'ERROR: Failed to retrieve repository details (HTTP status code {response_get_repository.status_code})')

    return json.loads(response_get_repository.content)['id']


def get_environment_public_key(github_token: str, organization_name: str, repository_name: str, environment_name: str) -> Dict[str, str]:
    """
    Retrieve public key value for encrypting environment level secrets
    :return: The public key details
    """
    repository_id = get_repository_id(github_token, organization_name, repository_name)
    response = requests.get(
        url=f'https://api.github.com/repositories/{repository_id}/environments/{environment_name}/secrets/public-key',
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )

    if response.status_code >= 300:
        raise Exception(f'ERROR: Failed to retrieve public key for secret encryption (HTTP status code {response.status_code})')

    return json.loads(response.content)


def encrypt_secret(public_key: str, secret_value: str) -> str:
    """
    Encrypt string for use in GitHub secrets
    :param public_key: The public key to use for encryption
    :param secret_value: The plain text value
    :return: The encrypted value
    """
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def upsert_environment_secret(
        github_token: str,
        organization_name: str,
        repository_name: str,
        environment_name: str,
        secret_name: str,
        secret_value: str
):
    repository_id = get_repository_id(github_token, organization_name, repository_name)
    public_key = get_environment_public_key(github_token, organization_name, repository_name, environment_name)
    response = requests.put(
        url=f'https://api.github.com/repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}',
        json={
            'key_id': public_key['key_id'],
            'encrypted_value': encrypt_secret(
                public_key=public_key['key'],
                secret_value=secret_value
            )
        },
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )
    if response.status_code >= 300:
        raise Exception(f'ERROR: Failed to upsert secret value (HTTP status code {response.status_code})')


def handler(event, context):
    """
    Lambda entrypoint
    :param event:
    :param context:
    :return:
    """
    errors = []

    # Get configuration from SSM
    ssm = boto3.client('ssm')

    try:
        print('Retrieving configuration...')
        github_token = ssm.get_parameter(Name=os.environ['github_token_ssm_parameter_name'], WithDecryption=True)['Parameter']['Value']
    except Exception as exception:
        print('ERROR: Failed to load all required SSM parameter values')
        print(exception)
        exit(1)

    try:
        github_organization = os.environ['github_organization']
        github_repository = os.environ['github_repository']
        github_environment = os.environ['github_environment']
        iam_username = os.environ['iam_username']

        # Exit if there were any errors
        if len(errors) > 0:
            for error in errors:
                print(error)
            exit(1)

        # Get IAM client
        iam = boto3.client('iam')

        # Delete all access keys currently on the user
        paginator = iam.get_paginator('list_access_keys')
        for response in paginator.paginate(UserName=iam_username):
            for iam_access_key in response['AccessKeyMetadata']:
                print(f'Deleting IAM Access Key: {iam_access_key["AccessKeyId"]}')
                iam.delete_access_key(
                    UserName=iam_username,
                    AccessKeyId=iam_access_key["AccessKeyId"]
                )

        # Create a new access key
        iam_access_key = iam.create_access_key(
            UserName=iam_username
        )
        if 'AccessKey' not in iam_access_key.keys():
            print('ERROR: Failed to create new access key')
            exit(1)
        print(f'Created IAM Access Key: {iam_access_key["AccessKey"]["AccessKeyId"]}')
        # Update GitHub Actions with the new secret values
        print('Updating "AWS_ACCESS_KEY_ID" environment secret')
        upsert_environment_secret(
            github_token=github_token,
            organization_name=github_organization,
            repository_name=github_repository,
            environment_name=github_environment,
            secret_name='AWS_ACCESS_KEY_ID',
            secret_value=iam_access_key['AccessKey']['AccessKeyId']
        )

        print('Updating "AWS_SECRET_ACCESS_KEY" environment secret')
        upsert_environment_secret(
            github_token=github_token,
            organization_name=github_organization,
            repository_name=github_repository,
            environment_name=github_environment,
            secret_name='AWS_SECRET_ACCESS_KEY',
            secret_value=iam_access_key['AccessKey']['SecretAccessKey']
        )

        print('Updating "AWS_DEFAULT_REGION" environment secret')
        upsert_environment_secret(
            github_token=github_token,
            organization_name=github_organization,
            repository_name=github_repository,
            environment_name=github_environment,
            secret_name='AWS_DEFAULT_REGION',
            secret_value='ap-southeast-2' if 'region' not in os.environ.keys() else os.environ['region']
        )
    except Exception as exception:
        print(f'EXCEPTION ERROR: {exception}')
        print('Skipping to next repository')