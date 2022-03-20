# (First section) Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# The following three functions in this file have been borrowed from Paramiko
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Useful functions used by the rest of paramiko.
"""
from struct import pack, unpack
# import long type
class long(int):
        pass

def byte_chr(c):
    assert isinstance(c, int)
    return pack("B", c)

def byte_ord(c):
    # In case we're handed a string instead of an int.
    if not isinstance(c, int):
        c = ord(c)
    return c

xffffffff = long(0xffffffff)
zero_byte = byte_chr(0)
max_byte = byte_chr(0xff)
deflate_zero = 0
deflate_ff = 0xff

def deflate_long(number, add_sign_padding=True):
    """turns a long-int into a normalized byte string
    (adapted from Crypto.Util.number)"""
    # after much testing, this algorithm was deemed to be the fastest
    bytestring = bytes()
    n = long(number)
    while (number != 0) and (number != -1):
        bytestring = pack(">I", n & xffffffff) + bytestring
        number >>= 32

    # strip off leading zeros, FFs
    for i in enumerate(bytestring):
        if (n == 0) and (i[1] != deflate_zero):
            break
        if (n == -1) and (i[1] != deflate_ff):
            break
    else:
        # degenerate case, n was either 0 or -1
        i = (0,)
        if n == 0:
            bytestring = zero_byte
        else:
            bytestring = max_byte
    bytestring = bytestring[i[0] :]
    if add_sign_padding:
        if (number == 0) and (byte_ord(bytestring[0]) >= 0x80):
            bytestring = zero_byte + bytestring
        if (number == -1) and (byte_ord(bytestring[0]) < 0x80):
            bytestring = max_byte + bytestring
    return bytestring

def inflate_long(bytestring, always_positive=False):
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    out = long(0)
    negative = 0
    if not always_positive and (len(bytestring) > 0) and (byte_ord(bytestring[0]) >= 0x80):
        negative = 1
    if len(bytestring) % 4:
        filler = zero_byte
        if negative:
            filler = max_byte
        # never convert this to ``s +=`` because this is a string, not a number
        # noinspection PyAugmentAssignment
        bytestring = filler * (4 - len(bytestring) % 4) + bytestring
    for i in range(0, len(bytestring), 4):
        out = (out << 32) + unpack(">I", bytestring[i : i + 4])[0]
    if negative:
        out -= long(1) << (8 * len(bytestring))
    return out

# END Paramiko-borrowed section

def encode_string(source_string, encoding: str = 'utf-8') -> bytes:
    if isinstance(source_string, str):
        source_string = source_string.encode(encoding)
        
    if isinstance(source_string, bytes):
        return pack('>I', len(source_string)) + source_string
    else:
        raise TypeError("Expected unicode or bytes, got {!r}. Try specifying a different encoding.".format(source_string))

def encode_boolean(source_bool: bool) -> bytes:
    return byte_chr(1) if source_bool else byte_chr(0)

def encode_int(source_int: int) -> bytes:
    return pack('>I', source_int)

def encode_int64(source_int: long) -> bytes:
    return pack('>Q', source_int)

def encode_mpint(source_int: long) -> bytes:
    if source_int < 0:
        raise ValueError("MPInts must be positive")
    
    return encode_string(deflate_long(source_int))

def encode_list(source_list: list, separator = ',') -> bytes:
    encode_string(separator.join(source_list))
    
def encode_alt_list(source_list: list) -> bytes:
    return encode_string(encode_string('').join([
            encode_string(x) for x in source_list
        ])
    )    