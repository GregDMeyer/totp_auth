#!/usr/bin/env python3

from time import time
from base64 import b32decode
from Crypto.Hash import SHA
from Crypto.Hash.HMAC import HMAC

INTERVAL = 30
CODE_LEN = 6

def current_interval(cur_time=None):
    '''
    Get the current interval.
    '''
    if cur_time is None:
        cur_time = time()
    t = int(cur_time)//INTERVAL
    return t

def compute_mac(key, cur_time=None):
    '''
    Compute the HMAC-SHA1 of the current interval using the KEY.
    '''
    interval = current_interval(cur_time)
    mac = HMAC(b32decode(key), msg=interval.to_bytes(byteorder='big', length=8), digestmod=SHA)
    return mac.digest()

def dynamic_truncate(mac):
    '''
    Do dynamic truncation of the MAC to generate a 4-byte string.
    '''
    offset = int(mac[-1]) & 0xF
    return mac[offset:offset+4]

def submac_to_code(submac):
    '''
    Convert the 4-byte string into a 6-digit code.
    '''
    number = int.from_bytes(submac, byteorder='big')
    number &= 0x7FFFFFFF  # spec says to drop the first bit "for interoperability"
    number %= 10**CODE_LEN
    return str(number).zfill(6)

def generate_code(key, cur_time=None):
    '''
    Generate a OTP code from the current time (in seconds past the epoch).
    '''
    mac = compute_mac(key, cur_time)
    submac = dynamic_truncate(mac)
    return submac_to_code(submac)

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser(description='Generate a OTP code.')
    parser.add_argument('--copy', action='store_true',
                        help='Copy OTP to clipboard instead of printing it.')

    args = parser.parse_args()

    key = 'DUMMYKEY'
    code = generate_code(key)
    if args.copy:
        import xerox
        xerox.copy(code)
    else:
        print(code)
