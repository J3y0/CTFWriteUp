from pwn import *
import re


if __name__ == "__main__":
    RHINO = "~c`°\^\)"

    HOST = "challenges.404ctf.fr"
    PORT = 31420
    r = remote(HOST, PORT)

    data = r.recvuntil(b">")
    print(data.decode())

    while True:
        picture = data.decode()

        matched = re.findall(RHINO, picture)

        nb = len(matched)

        r.sendline(str(nb).encode())

        try:
            data = r.recvuntil(b">")
            print(data.decode())
        except:
            flag = r.recvuntil(b"}")
            print(flag)
            break

# Flag: 404CTF{4h,_l3s_P0uvo1rs_d3_l'iNforM4tiqu3!}
