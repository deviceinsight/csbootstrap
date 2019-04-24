#!/usr/bin/env python3

from subprocess import call
import base64
import requests
import json
import argparse
import sys
from OpenSSL import crypto, SSL
from collections import namedtuple

BootstrapInfo = namedtuple(
    'BootstrapInfo', 'token bootstrap_url renewal_url urn')

KEY_FILE_NAME = 'client-key.pem'
CERT_FILE_NAME = 'client-cert.pem'
CSR_FILE_NAME = 'client-csr.pem'


def generate_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key


def generate_csr(common_name, key):
    req = crypto.X509Req()
    req.get_subject().CN = common_name

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    return req


def write_key(path, key):
    with open(path, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        print('Created ' + path)


def read_key(path):
    with open(path, 'rb') as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())


def write_csr(path, req):
    with open(path, 'wb') as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        print('Created ' + path)


def write_cert(path, cert):
    with open(path, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        print('Created ' + path)


def load_bootstrap_info(path):
    if path == '-':
        bootstrap_info = json.load(sys.stdin)

    else:
        with open(path, 'r') as f:
            bootstrap_info = json.load(f)

    token = bootstrap_info['bootstrapToken']
    bootstrap_url = bootstrap_info['bootstrapUrl']
    renewal_url = bootstrap_info['renewalUrl']
    gateway_urn = bootstrap_info['gatewayUrn']
    return BootstrapInfo(token=token, bootstrap_url=bootstrap_url, renewal_url=renewal_url,
                         urn=gateway_urn)


def request_certificate(csr, bootstrap_info, path, renew=False):
    csr_bytes = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr)
    csr_b64 = base64.encodebytes(csr_bytes).decode('utf-8').replace('\n', '')

    body = {'csr': csr_b64}
    if not renew:
        body['token'] = bootstrap_info.token

    print(body)

    url = bootstrap_info.renewal_url if renew else bootstrap_info.bootstrap_url
    if renew:
        client_key = path + '/' + KEY_FILE_NAME
        client_cert = path + '/' + CERT_FILE_NAME
        r = requests.post(url, json=body, cert=(
            client_cert, client_key), verify=False)
    else:
        r = requests.post(url, json=body)

    r.raise_for_status()

    certificate_b64 = r.json()['certificate']
    certificate_bytes = base64.decodebytes(certificate_b64.encode('utf-8'))
    certificate = crypto.load_certificate(
        crypto.FILETYPE_ASN1, certificate_bytes)
    return certificate


def bootstrap(bootstrap_info, path):
    key = generate_key()
    csr = generate_csr(bootstrap_info.urn, key)
    write_key(path + '/' + KEY_FILE_NAME, key)
    write_csr(path + '/' + CSR_FILE_NAME, csr)
    cert = request_certificate(csr, bootstrap_info, path)
    write_cert(path + '/' + CERT_FILE_NAME, cert)


def renew(bootstrap_info, path):
    key = read_key(path + '/' + KEY_FILE_NAME)
    csr = generate_csr(bootstrap_info.urn, key)
    write_csr(path + '/' + CSR_FILE_NAME, csr)
    request_certificate(csr, bootstrap_info, path, renew=True)


def main():
    parser = argparse.ArgumentParser(
        description='Get a certificate for a device.')

    parser.add_argument('action', action='store', default='bootstrap',
                        choices=['bootstrap', 'renew'],
                        help='Whether to bootstrap a new certificate or renew an existing one.'
                        ' Renewing an existing certificate requires a valid key and certificate'
                        " to exist in the 'path'.")

    parser.add_argument('-b', '--bootstrap-info', dest='bootstrap_info', action='store', default='-',
                        help="Path to the bootstrap.json file or for '-' stdin.")

    parser.add_argument('-p', '--path', dest='path', action='store', default='.',
                        help='Path to save the generated files (key, CSR, certificate) to'
                        ' and where the key file is expected on renewal.')

    args = parser.parse_args()

    bootstrap_info = load_bootstrap_info(args.bootstrap_info)
    if args.action == 'bootstrap':
        bootstrap(bootstrap_info, args.path)
    else:
        renew(bootstrap_info, args.path)


if __name__ == "__main__":
    main()
