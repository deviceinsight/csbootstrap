#!/usr/bin/env python3

from subprocess import call
import base64
import requests
import json
import argparse
import sys
from OpenSSL import crypto, SSL
from collections import namedtuple

BootstrapInfo = namedtuple('BootstrapInfo', 'token url urn')


def generate_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key


def generate_csr(common_name):
    req = crypto.X509Req()
    req.get_subject().CN = common_name

    key = generate_key()
    req.set_pubkey(key)
    req.sign(key, "sha256")

    return (req, key)


def write_key(path, key):
    with open(path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        print("Created " + path)


def write_csr(path, req):
    with open(path, "wb") as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        print("Created " + path)


def write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        print("Created " + path)


def load_bootstrap_info(path):
    if path == '-':
        bootstrap_info = json.load(sys.stdin)

    else:
        with open(path, "r") as f:
            bootstrap_info = json.load(f)

    token = bootstrap_info["bootstrapToken"]
    bootstrap_url = bootstrap_info["bootstrapUrl"]
    gateway_urn = bootstrap_info["gatewayUrn"]
    return BootstrapInfo(token=token, url=bootstrap_url, urn=gateway_urn)


def request_certificate(csr, bootstrap_info):
    csr_bytes = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr)
    csr_b64 = base64.encodebytes(csr_bytes).decode("utf-8").replace("\n", "")

    body = {'csr': csr_b64, 'token': bootstrap_info.token}
    print(body)

    r = requests.post(bootstrap_info.url, json=body)
    r.raise_for_status()

    certificate_b64 = r.json()["certificate"]
    certificate_bytes = base64.decodebytes(certificate_b64.encode("utf-8"))
    certificate = crypto.load_certificate(
        crypto.FILETYPE_ASN1, certificate_bytes)
    return certificate

def main():
    parser = argparse.ArgumentParser(
        description='Get a certificate for a device.')

    parser.add_argument('--bootstrap-info', dest='bootstrap_info', action='store', default='-',
                        help="Path to the bootstrap.json file or for '-' stdin")

    parser.add_argument('--output', dest='output', action='store', default='.',
                        help='Path to save the generated files (key, CSR, certificate) to')

    args = parser.parse_args()

    bootstrap_info = load_bootstrap_info(args.bootstrap_info)
    (csr, key) = generate_csr(bootstrap_info.urn)
    write_key(args.output + '/client-key.pem', key)
    write_csr(args.output + '/client-csr.pem', csr)
    cert = request_certificate(csr, bootstrap_info)
    write_cert(args.output + '/client-cert.pem', cert)
