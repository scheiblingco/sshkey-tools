# pylint: disable-all
from paramiko.ecdsakey import ECDSAKey
from paramiko.message import Message
from cryptography.hazmat.primitives.asymmetric import ec
from paramiko.util import deflate_long
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from struct import pack, unpack
from cryptography.utils import int_to_bytes

from binascii import unhexlify

def long_to_bytes (val, padding=True, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s

# def crypfun 

mess = Message()
mess.add_string('Hello')
mess.add_string('World')

key = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')

ecdsa = ec.ECDSA(key.ecdsa_curve.hash_object())
sig = key.signing_key.sign(mess.asbytes(), ecdsa)
r1, s1 = decode_dss_signature(sig)

# print(int.to_bytes(r1, 32, 'big'))
# print(deflate_long(r1))
# try:
#     print(int_to_bytes(r1, 32))
# except:
#     print(int_to_bytes(r1, 33))

# print(int_to_bytes(r1, 34))
# print(long_to_bytes(r1))
# n = 123456789012345671
# n >>= 32
# print(n)
