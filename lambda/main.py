import json
import boto3
import time


def lambda_handler(event, context):

    csr = event['csr']

    cert_auth_arn = get_certificate_authority_arn()

    cert_arn = sign_certificate(cert_auth_arn, csr)

    time.sleep(5)

    cert_pem = get_certificate_pem(
        cert_authority = cert_auth_arn,
        cert_arn = cert_arn
    )

    result = updateParameterStore(cert_pem)

    print(result)

    return {
        'statusCode': result['ResponseMetadata']['HTTPStatusCode']
    }


def get_certificate_authority_arn(common_name='ca.shared.aws.gs.com'):

    pca = boto3.client('acm-pca')

    res = pca.list_certificate_authorities()

    for ca in res['CertificateAuthorities']:
        if ca['CertificateAuthorityConfiguration']['Subject']['CommonName'] == common_name:
            CA = ca['Arn']

            return CA

    print(f"certificate authority {common_name} not found")


def sign_certificate(cert_auth_arn, csr):

    pca = boto3.client('acm-pca')

    res = pca.issue_certificate(
        CertificateAuthorityArn=cert_auth_arn,
        Csr=csr,
        SigningAlgorithm='SHA512WITHRSA',
        TemplateArn='arn:aws:acm-pca:::template/EndEntityCertificate/V1',
        Validity={
            'Value': 365,
            'Type': 'DAYS'
        },
        IdempotencyToken='60'
    )

    print(f"Sign Cert results: {res}")

    cert_arn = res['CertificateArn']

    print(f"cert_arn: {cert_arn}")

    return cert_arn


def updateParameterStore(cert_pem):

    ssm_client = boto3.client("ssm")

    new_string_parameter = ssm_client.put_parameter(
        Name='/infra/billpay/billgo-mtls-pem-6-26-22',
        Description='Billgo Certificate for mTLS',
        Value=cert_pem,
        Type='String',
        Overwrite=True,
        Tier='Standard',
        DataType='text'
    )

    print(f"New Parameter Store key result: {new_string_parameter}")

    return new_string_parameter


def get_certificate_pem(cert_authority, cert_arn):

    pca = boto3.client('acm-pca')

    res = pca.get_certificate(
        CertificateAuthorityArn=cert_authority,
        CertificateArn=cert_arn
    )

    cert_pem = res['Certificate']

    print(f"cert pem result: {cert_pem}")

    return cert_pem
