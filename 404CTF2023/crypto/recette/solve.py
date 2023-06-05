import re
import base64

hexa = "32 69 31 73 34 69 31 73 31 35 64 31 6f 34 39 69 31 6f 34 64 31 6f 33 69 31 6f 31 35 64 31 6f 32 32 64 31 6f 32 30 64 31 6f 31 39 69 31 6f 37 64 31 6f 35 64 31 6f 32 69 31 6f 35 35 69 31 6f 31 64 31 6f 31 39 64 31 6f 31 37 64 31 6f 31 38 64 31 6f 32 39 69 31 6f 31 32 69 31 6f 32 36 69 31 6f 38 64 31 6f 35 39 64 31 6f 32 37 69 31 6f 36 64 31 6f 31 37 69 31 6f 31 32 64 31 6f 37 64 31 6f 35 69 31 6f 31 64 31 6f 32 64 31 6f 31 32 69 31 6f 39 64 31 6f 32 36 64 31 6f"
hexa = hexa.split(" ")

decoded_hexa = ""

for elt in hexa:
    decoded_hexa += chr(int(elt, 16))

deadfish = ""

numbers = re.findall("\d+", decoded_hexa)
chars = re.findall("[a-z]", decoded_hexa)

for i in range(len(numbers)):
    deadfish += int(numbers[i])*chars[i]

print(deadfish)

base85_str = "1b^aR<(;4/1hgTC1NZtl1LFWKDIHFRI/"

flag = base64.a85decode(base85_str.encode())
print(flag)

# 404CTF{M4igr3t_D3_c4naRd}
