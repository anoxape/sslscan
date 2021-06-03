#!/usr/bin/env python3
"""SSL certificate scanner.

Scans through a list of websites, captures SSL Server Certificate security details,
sorts Certificates' data as per their validity, and exports data file.
"""

from concurrent import futures
from enum import Enum
from typing import Any, Dict, List, NamedTuple, NewType

import socket
import ssl

from OpenSSL import crypto


Certificate = NewType('Certificate', Any)  # ssl getpeercert doesn't declare a return type


class CertificateStatus(Enum):
    VALID = 1
    INVALID = 2
    UNAVAILABLE = 3


CertificateData = NamedTuple('CertificateInfo',
                             hostname=str,
                             status=CertificateStatus,
                             certificate=Certificate)

HTTPS_PORT = 443


def _get_certificate(hostname: str, context: ssl.SSLContext):
    with socket.create_connection((hostname, HTTPS_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert(binary_form=True)


def get_certificate(hostname: str) -> CertificateData:
    context = ssl.create_default_context()
    try:
        return CertificateData(hostname=hostname,
                               status=CertificateStatus.VALID,
                               certificate=_get_certificate(hostname, context))
    except ssl.SSLCertVerificationError:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return CertificateData(hostname=hostname,
                               status=CertificateStatus.INVALID,
                               certificate=_get_certificate(hostname, context))
    except ssl.SSLError:
        return CertificateData(hostname=hostname,
                               status=CertificateStatus.UNAVAILABLE,
                               certificate=None)


def dump_certificate(certificate: Certificate) -> str:
    crypto_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
    return crypto.dump_certificate(crypto.FILETYPE_TEXT, crypto_certificate).decode('ASCII')


def get_certificates(hostnames: List[str]) -> Dict[CertificateStatus, Dict[str, Certificate]]:
    certificates = {status: {} for status in CertificateStatus}
    with futures.ThreadPoolExecutor() as executor:
        for data in executor.map(get_certificate, hostnames):
            certificates[data.status][data.hostname] = data.certificate
    return certificates


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=argparse.FileType('r'), nargs='?', default=sys.stdin,
                        help='list of websites (file name or - for stdin, defaults to stdin)')
    parser.add_argument('output', type=argparse.FileType('w'), nargs='?', default=sys.stdout,
                        help='certificate data (file name or - for stdout, defaults to stdout)')
    args = parser.parse_args()

    certificates = get_certificates(args.input.read().splitlines())

    with args.output as output:
        for status in CertificateStatus:
            if certificates[status]:
                output.write(f"*** {status.name} ***\n\n")
                for hostname, certificate in certificates[status].items():
                    output.write(f"Hostname: {hostname}\n")
                    if certificate is not None:
                        output.write(dump_certificate(certificate))
                    output.write('\n')


if __name__ == '__main__':
    main()
