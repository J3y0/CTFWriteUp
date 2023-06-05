import binascii
import string

secret = "49 b7 71 9f 90 cc 74 9f ca a4 64 b9 83 7a 9e 5e".split(" ")

test_input = "I_want_my_coffee"

flag = b"\x00"
for i in range(len(secret)):
    cipher = binascii.unhexlify(secret[i])
    print(f"{cipher =} and {flag[i] = }")
    dif = int.from_bytes(cipher) - flag[i]
    print(dif)
    plain = dif^flag[i]
    print(f"{plain = }")
    flag += chr(plain).encode()

print(flag)
