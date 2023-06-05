import string


def find_index(char):
    for i in range(len(string.ascii_lowercase)):
        if string.ascii_lowercase[i] == char:
            return i
    return "Not found"


def shift(text, shift):
    result = ""
    for c in text:
        result += string.ascii_lowercase[(find_index(c) + shift)%26]
    return result


def delta_idx(char1, char2):
    return ord(char1) - ord(char2)


def cipher(plain, ref_cipher):
    cipher = ref_cipher

    # Offset introduced by letter
    for i in range(len(plain)):
        char = plain[i]
        delta = delta_idx(char, "a")
        for j in range(len(plain) - i):
            cipher = cipher[:j] + shift(cipher[j:], delta)

    return cipher


def decipher(cipher, ref_cipher):
    plain = ""
    all_shift = [0]
    for i in range(len(cipher)-2, -1, -1):
        delta = delta_idx(cipher[i+1], ref_cipher[i+1])
        delta_prev = delta_idx(cipher[i], ref_cipher[i])
        brought_delta_by_plain_letter = delta - delta_prev - sum(all_shift)

        plain_letter = shift("a", brought_delta_by_plain_letter)
        all_shift.append(brought_delta_by_plain_letter)
        plain += plain_letter

    last_letter = shift("a", delta_idx(cipher[0], ref_cipher[0]) - sum(all_shift))
    plain += last_letter

    return plain


ref = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ref_cipher = "gvshnmijdwalablggmejiqvrhkixhns"

flag_cipher = "pvfdhtuwgbpxfhocidqcznupamzsezp"

print(decipher(flag_cipher, ref_cipher))

# FLAG: 404CTF{lenclumedesjourneesensoleillees}
