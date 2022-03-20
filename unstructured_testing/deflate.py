# # # pylint: disable-all
# # import random, math

# # # print(10**3)
# # # length = 
# # res = {}
# # lastnr = 0
# # lastctr = 0
# # ctr = 0
# # for x in range(100):
# #     y = 0
# #     inte = random.randint(10**x, 10**(x+1))
# #     test = False
# #     while test == False:
# #         y += 1
# #         try:
# #             int.to_bytes(inte, y, 'big')
# #             print(f"{x} fits in {y}")
# #             check = math.ceil(math.log(inte)/math.log(256))
# #             if check == y:
# #                 print("Success!")
# #             else:
# #                 print(check)
# #             ctr += 1
# #             if lastnr == y:
# #                 lastctr += 1
# #                 if lastctr == 3:
# #                     lastctr = 0
# #                     print("3!")
# #                     print(ctr)
# #                     ctr = 0
# #             lastnr = y
# #             test = True
# #         except OverflowError:
# #             pass
        
# # print(res)

# # test = deflate_long(1234567890)
# # # test2 = int.to_bytes(8571611219489, 5, 'big')

# # print(len(str(8571611219489)))
# # print(test)
# # print(test2)

# # print(int.from_bytes(test, byteorder='big'))
# # # print(11223344556677889900.to_bytes())
# # # print(compress(11223344556677889900))
# # from paramiko.py3compat import PY2, long, byte_chr, byte_ord, b

# # print(int(0xff000000))

# import os
# import math
# import random
# import struct
# from time import time
# from base64 import b64encode, b64decode
# from struct import pack
# from paramiko.message import Message
# from paramiko.ecdsakey import ECDSAKey
# from paramiko.util import deflate_long

# # Import cryptography functionality
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.asymmetric.utils import (
#     decode_dss_signature,
#     encode_dss_signature,
# )

# def byte_chr(c):
#     assert isinstance(c, int)
#     return struct.pack("B", c)
# max_byte = byte_chr(0xff)
# zero_byte = byte_chr(0)

# class long(int):
#         pass

# def byte_ord(c):
#     # In case we're handed a string instead of an int.
#     if not isinstance(c, int):
#         c = ord(c)
#     return c

# deflate_zero = 0
# deflate_ff = 0xff
# xffffffff = long(0xffffffff)

# def deflate_long(n, add_sign_padding=True):
#     """turns a long-int into a normalized byte string
#     (adapted from Crypto.Util.number)"""
#     # after much testing, this algorithm was deemed to be the fastest
#     s = bytes()
#     n = long(n)
#     while (n != 0) and (n != -1):
#         s = struct.pack(">I", n & xffffffff) + s
#         n >>= 32
#     # strip off leading zeros, FFs
#     for i in enumerate(s):
#         if (n == 0) and (i[1] != deflate_zero):
#             break
#         if (n == -1) and (i[1] != deflate_ff):
#             break
#     else:
#         # degenerate case, n was either 0 or -1
#         i = (0,)
#         if n == 0:
#             s = zero_byte
#         else:
#             s = max_byte
#     s = s[i[0] :]
#     if add_sign_padding:
#         if (n == 0) and (byte_ord(s[0]) >= 0x80):
#             s = zero_byte + s
#         if (n == -1) and (byte_ord(s[0]) < 0x80):
#             s = max_byte + s
#     return s


# # Create sample data to be signed
# s_data = Message()
# s_data.add_string('Hello')
# s_data.add_string('World')
# s_data.add_string('!')

# # Import the signing key
# parakey = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')
# with open('testcerts/ecdsa_ca', 'rb') as f:
#     cryptokey = f.read()
#     cryptokey = serialization.load_ssh_private_key(cryptokey, None)
    
# # parasig = parakey.sign_ssh_data(s_data.asbytes())

# cryptosig = cryptokey.sign(
#     s_data.asbytes(),
#     ec.ECDSA(hashes.SHA256())
# )

# # def long_to_bytes(l_val):  
# #     b_len = math.ceil(math.log(l_val)/math.log(256))
# #     return b_len, int.to_bytes(l_val, b_len, 'big')

# # def encodeMpint(num):
# #     leng, byt = long_to_bytes(num)
# #     return pack('>I', leng) + byt

# r1, s1 = decode_dss_signature(cryptosig)


# def encodeMpint(num, plus=0):
#     b_len = math.ceil(math.log(num)/math.log(256))
    
#     return int.to_bytes(num, b_len, 'big')


# print(r1)
# print(deflate_long(r1))
# print(encodeMpint(r1))
# print(encodeMpint(r1, 1))

# # r1 = encodeMpint(r1)
# # s2 = encodeMpint(s1)
# # r2, s2 = parakey.sign_ssh_data(s_data.asbytes())

# # print(r1)
# # print(r2)