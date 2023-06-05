import collections
from functools import cmp_to_key
from pwn import *

voyelle = "aeiouy"
consonne = "bcdfghjklmnpqrstvwxz" + "bcdfghjklmnpqrstvwxz".upper()

def rule0(word):
    return word

def rule1(word):
    return word[::-1]

def rule2(word):
    if len(word)%2 == 0:
        word = word[len(word)//2:] + word[:len(word)//2]
        return word
    else:
        letter = word[len(word)//2]
        word = word.replace(letter, "")
    return word

def shift_voy(word, voy, shift):
    new_word = ""
    voy = collections.deque(voy)
    voy.rotate(shift)
    voy = list(voy)

    j = 0
    for i in range(len(word)):
        if word[i] not in voyelle:
            new_word += word[i]
        else:
            new_word += voy[j]
            j += 1

    return new_word

def rule3(rule2_out, word):
    voy = []
    for i in range(len(word)):
        if word[i] in voyelle:
            voy.append(word[i])

    if len(rule2_out) >= 3:
        if rule2_out[2] in voyelle:
            word = shift_voy(word, voy, 1)
        else:
            word = shift_voy(word, voy, -1)
        word = rule1(word)
        word = rule2(word)
    else:
        word = rule2_out

    return word

def prec_voy(c):
    import string
    global voyelle
    voyelle_with_maj = voyelle + voyelle.upper()
    # Find index
    for i in range(len(string.ascii_letters)):
        if c == string.ascii_letters[i]:
            index = i
            break

    # Find previous voyelle
    next = 0
    for i in range(index, -1, -1):
        if string.ascii_letters[i] in voyelle_with_maj:
            next = string.ascii_letters[i]
            break
    return ord(next)

def is_voyelle(c):
    global voyelle
    voyelle_with_maj = voyelle + voyelle.upper()
    if c in voyelle_with_maj:
        return 1
    else:
        return 0

def compute_sum(n, word):
    sum = 0
    for i in range(n-1, -1, -1):
        sum += (2**(n - i))*ord(word[i])*is_voyelle(word[i])
    return sum

def cmp_sort_letters(elt1, elt2):
    if elt1[1] > elt2[1]: 
        return -1
    elif elt1[1] < elt2[1]:
        return 1
    else:
        return ord(elt1[0]) - ord(elt2[0])

def rule4(word):
    n = 0
    while n < len(word):
        c = word[n]
        if c in consonne:
            after = word[n+1:]
            vp = prec_voy(c)
            s = compute_sum(n, word)
            new_char = chr((vp + s)%95 + 32)
            word = word[:n+1] + new_char + after
        n += 1
    # Sort the word
    occ = collections.Counter(word)
    letters = list(occ.items())
    letters.sort(key=cmp_to_key(cmp_sort_letters))
    return "".join([x[0]*x[1] for x in letters])

HOST = "challenges.404ctf.fr"
PORT = 30980
r = remote(HOST, PORT)

data = r.recvuntil(b">> ").decode()
print(data)

input = data.split("Entrée : {")[1].split("}")[0]
print(input)

# Init
compt = 1
while compt <= 5:
    init_word = input
    for i in range(compt):
        if i == 0:
            print("Rule 0 applied: ", input)
            input = rule0(input)
        if i == 1:
            input = rule1(input)
            print("Rule 1 applied: ", input)
        if i == 2:
            input = rule2(input)
            print("Rule 2 applied: ", input)
        if i == 3:
            input = rule3(input, init_word)
            print("Rule 3 applied: ", input)
        if i == 4:
            input = rule4(input)
            print("Rule 4 applied: ", input)

    payload = input
    print(f"Payload nb {compt}: ", payload)
    r.sendline(payload.encode())

    data = r.recvuntil(b">> ").decode()
    print(data)

    input = data.split("Entrée : {")[1].split("}")[0]
    print("INPUT: ",input)
    compt += 1

words = input.split(" ")
# Translate chapter
payload = ""
for w in words:
    translated = rule4(rule3(rule2(rule1(w)), w))
    payload += translated + " "

payload = payload[:len(payload) - 1] # remove trailing space
print(payload)
r.sendline(payload.encode())

flag = r.recvuntil(b"}").decode()
print(flag)
