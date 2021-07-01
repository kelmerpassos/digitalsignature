from OpenSSL import crypto
import argparse
import re
from os.path import isfile
import traceback
import sys

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

def create_args():
    """Creates CLI arguments for the script."""

    parser = argparse.ArgumentParser(description='Script for digitally signing a pdf')
    parser.add_argument('pfx_certificate', type=str, help='Specify keystore file in .pfx format (Mandatory)')
    parser.add_argument('password', type=str, help=' Specify password for keystore file (mandatory)')
    parser.add_argument('src', type=str,
        help='Specify the source file that needs to be digitally signed. Only 1 file at a time can be signed. (Mandatory) ')
    return parser.parse_args()

def validate_args(args):
    """Validating commandline arguments raises valueError exception with if any command
    line arguments are not valid."""

    IS_PFX = lambda pfx_certificate: re.match( r'^(.[^,]+)(.pfx|.PFX){1}$', pfx_certificate)
    if not IS_PFX(args.pfx_certificate):
        raise ValueError('Not a proper pfx file with .pfx or .PFX extension')
    if not isfile(args.src):
        raise ValueError('File not found')

def sign_p7 (path_cert:str, password:str, json:str, output:str):
    with open (path_cert, 'rb') as file:
        pfx_buffer = file.read()
    p12 = crypto.load_pkcs12 (pfx_buffer, password.encode())
    signcert = p12.get_certificate ()
    pkey = p12.get_privatekey ()
    bio_in = crypto._new_mem_buf (json.encode())

    # define PKCS7_TEXT 0x1
    # define PKCS7_NOCERTS 0x2
    # define PKCS7_NOSIGS 0x4
    # define PKCS7_NOCHAIN ​​0x8
    # define PKCS7_NOINTERN 0x10
    # define PKCS7_NOVERIFY 0x20
    # define PKCS7_DETACHED 0x40
    # define PKCS7_BINARY 0x80
    # define PKCS7_NOATTR 0x100
    # define PKCS7_NOSMIMECAP 0x200
    # define PKCS7_NOOLDMIMETYPE 0x400
    # define PKCS7_CRLFEOL 0x800
    # define PKCS7_STREAM 0x1000
    # define PKCS7_NOCRL 0x2000

    PKCS7_TEXT = 0x1
    PKCS7_NOSIGS = 0x4
    PKCS7_DETACHED = 0x40
    PKCS7_NOATTR = 0x100
    PKCS7_NOSMIMECAP = 0x200
    PKCS7_PARTIAL = 0x4000

    # The default is to use the SHA256 algorithm, and there is no way to switch to SHA1
    pkcs7 = crypto._lib.PKCS7_sign (signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, PKCS7_NOSIGS)
    bio_out = crypto._new_mem_buf ()
    crypto._lib.i2d_PKCS7_bio (bio_out, pkcs7)
    sigbytes = crypto._bio_to_string (bio_out)
    with open (output,'wb') as file:
        file.write (sigbytes)

def run():
    args = create_args()

    try:
        validate_args(args)
    except ValueError as e:
        traceback.print_exc()
        sys.exit(1)
    with open(args.src, 'r') as file:
        json = file.read()
    try:
        sign_p7(
            args.pfx_certificate, 
            args.password,
            json,
            f'{args.src}.p7s'
        )
    except ValueError as e:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("Sign start ...")
    run()
    print("sign end ...")