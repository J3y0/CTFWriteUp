import subprocess
import binascii
from pwn import xor

DISAS = "objdump -M intel -d"
DATA = "objdump -j .data -s"


def retrieve_data(data_lines, offset, length_offset):
    result = ""
    length_result = ""
    collect = False
    for i in range(len(data_lines)):
        line = data_lines[i]
        splitted = line.split(" ")
        splitted.pop(0)  # remove empty line
        splitted.pop(-1)  # remove ascii repr
        address = splitted[0]
        splitted.pop(0)  # remove address

        if data_lines[i+1] == "":
            data_lines[i+1] = " " + hex(int(address, 16) + 0x10)[2:]
        if int(address, 16) <= offset and offset < int(data_lines[i+1].split(" ")[1], 16): # should test between
            # print(line)
            collect = True

        if collect:
            result += "".join(splitted)[:32]

        if int(address, 16) <= length_offset and length_offset < int(data_lines[i+1].split(" ")[1], 16):
            # print(line)
            shift = 2*(length_offset - int(address, 16))
            length_result = int.from_bytes(binascii.unhexlify("".join(splitted)[:32][shift:shift+8]), 'little')
            last_line_count = i
            break

    return result[:length_result*2], length_result, last_line_count


def find_offset(line) -> str:
    return int(line.split("# ")[1].split(" <")[0], 16)


def parse_info(exec_path, cpt):
    disas_cmd = DISAS.split(" ")
    disas_cmd.append(exec_path)
    disas_proc = subprocess.Popen(
        disas_cmd,
        stdout=subprocess.PIPE
    )
    disas_result = disas_proc.stdout.read().decode()    

    instr = disas_result.split("\n")
    # Get rid of useless asm
    while ".text" not in instr[0]:
        instr.pop(0)
    while "puts" not in instr[0]:
        instr.pop(0)
    while "puts" not in instr[0]:
        instr.pop(0)

    # Very ugly but at the end it seems to work
    for line in instr:
        # Get code offset
        if "lea    rdx" in line:
            code_off = find_offset(line)

        # Get key_length offset
        if "mov    ecx,DWORD PTR" in line:
            key_length_off = find_offset(line)

        # Get key offset
        if "lea    rax" in line:
            key_off = find_offset(line)

        # Get code_length offset
        if "mov    eax,DWORD PTR [rip" in line:
            code_length_offset = find_offset(line)

    print("Code offset: ", hex(code_off))
    print("Code len offset: ", hex(code_length_offset))
    print("Key offset: ", hex(key_off))
    print("Key len offset: ", hex(key_length_off))

    data_cmd = DATA.split(" ")
    data_cmd.append(exec_path)
    data_proc = subprocess.Popen(
        data_cmd,
        stdout=subprocess.PIPE
    )
    data_result = data_proc.stdout.read().decode()
    data_lines = data_result.split("\n")[4:]

    code, code_length, last_line = retrieve_data(data_lines, code_off, code_length_offset)
    key, key_length, _ = retrieve_data(data_lines[last_line:], key_off, key_length_off)
    print("    Code length: ", hex(code_length))
    print("    Key length: ", hex(key_length))

    output = open("./scripted_extract/code_extracted" + str(cpt), "wb")
    output.write(xor(binascii.unhexlify(code), binascii.unhexlify(key)))
    output.close()


i = 0
while True:  # Je suis un bourrin je sais -> En gros il le fait 100-101 fois
    print("\nFile nb ", i)  # File 0 is the source executable given
    parse_info("./scripted_extract/code_extracted" + str(i), i+1)
    i += 1

# Flag 404CTF{5t3althy_f1Le$-4nD_aUt0matIon}
