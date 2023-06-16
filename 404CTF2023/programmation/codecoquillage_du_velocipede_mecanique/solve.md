# First look

In this series of challenges around the `Velocipede Mecanique`, we are given an `ELF` program named `vm`, and another file with the `.vmr` extension.

I will consider for the rest of this WU you have whether reversed the `vm` program and understood it, whether read another WU on the challenge `Decortique mon Velocipede Mecanique`. ([here](../../reverse/decortique_mon_velocipede_mecanique/solve.md) is one if not, I would recommand reading it before this one).

Alright, what does the `.vmr` file looks like !

```bash
$ hexdump -C shellcode_my_vm_redacted.vmr 
00000000  01 09 72 65 61 64 5f 66  6c 61 67 02 3a 46 53 3a  |..read_flag.:FS:|
00000010  43 41 23 44 17 d5 0c 00  2b 41 42 2d 41 44 20 21  |CA#D....+AB-AD !|
00000020  6c 00 00 00 3a 41 42 23  44 01 00 00 00 5e 42 42  |l...:AB#D....^BB|
00000030  2b 42 43 2d 41 44 21 f9  ff ff ff 23 44 3c 83 03  |+BC-AD!....#D<..|
00000040  da 3a 41 42 2d 41 44 20  21 43 00 00 00 7c 09 00  |.:AB-AD !C...|..|
00000050  00 00 00 00 00 00 00 00  00 00 00 23 44 08 00 00  |...........#D...|
00000060  00 2b 53 44 23 43 72 c2  4e 9f 5e 43 42 3e 43 23  |.+SD#Cr.N.^CB>C#|
00000070  43 7a c2 48 9f 5e 43 42  3e 43 3a 41 53 23 42 25  |Cz.H.^CB>C:AS#B%|
00000080  00 00 00 2f 3a 41 53 24  3a 53 46 29 7c 27 00 00  |.../:AS$:SF)|'..|
00000090  00 43 6f 6e 64 69 74 69  6f 6e 73 20 6e 6f 74 20  |.Conditions not |
000000a0  6d 65 74 2c 20 6e 6f 74  20 73 68 6f 77 69 6e 67  |met, not showing|
000000b0  20 66 6c 61 67 2e 0a 00  3a 41 53 24 2e 01 08 61  | flag...:AS$...a|
000000c0  73 6b 5f 63 6f 64 65 02  3a 46 53 7c 1e 00 00 00  |sk_code.:FS|....|
000000d0  50 6c 65 61 73 65 20 65  6e 74 65 72 20 79 6f 75  |Please enter you|
000000e0  72 20 73 68 65 6c 6c 63  6f 64 65 3a 20 00 3a 41  |r shellcode: .:A|
000000f0  53 24 23 42 e8 03 00 00  25 3a 53 46 29 01 04 6d  |S$#B....%:SF)..m|
00000100  61 69 6e 02 28 08 61 73  6b 5f 63 6f 64 65 28 09  |ain.(.ask_code(.|
00000110  73 68 65 6c 6c 63 6f 64  65 28 09 72 65 61 64 5f  |shellcode(.read_|
00000120  66 6c 61 67 5e 41 41 2e                           |flag^AA.|
```

Looks like there are several functions: `main`, `ask_code`, `read_flag` and a `shellcode` function is called but I cannot find it within this file.

I can guess this is the function we have to write and pass to the program thanks to `ask_code` function.

# Analyzing `.vmr` file

First, let's understand what we need to do to call `read_flag` function ! Here is a view of the above hexadecimal from the `.vmr` file but on each line is an instruction:

```bash
## read_flag FUNCTION
01 09 72 65 61 64 5f 66 6c 61 67 02  # read_flag function header
3a 46 53  # Move top_of_local_stack value into REG5
3a 43 41  # Move REG0 value into REG2
23 44 17 d5 0c 00  # Store 0x0cd517 into REG3
2b 41 42  # Add REG0 and REG1
2d 41 44  # Sub REG3 to REG0
20  # NOP operation
21 6c 00 00 00  # If REG0 == 0 continue else jump at error handling branch
3a 41 42  # Store REG1 into REG0
23 44 01 00 00 00  # Store 0x01 into REG3
5e 42 42  # XOR REG1 with itself -> REG1 = 0
2b 42 43  # Add REG1 and REG2  <-------------------------------------------\
2d 41 44  # Sub REG3 to REG0                                               |
21 f9 ff ff ff # If REG0 == 0 continue, else loop over --------------------/
23 44 3c 83 03 da  # Store 0xda03833c into REG3
3a 41 42  # Store REG1 into REG0
2d 41 44  # Sub REG3 to REG0
20  # NOP operation
21 43 00 00 00  # If REG0 == 0 continue, else jump at error handling branch
7c 09 00 00 00 00 00 00 00 00 00 00 00 00  # Store on local stack 9 NULL bytes
23 44 08 00 00 00  # Store 0x08 into REG3
2b 53 44  # Add to top_of_local_stack REG3 value (REG3 = 0x8)
23 43 72 c2 4e 9f  # Store 0x9f4ec272 into REG2
5e 43 42  # Xor above value with REG1
3e 43  # Store value in REG2 to the stack (result of XOR operation)
23 43 7a c2 48 9f  # Store 0x9f48c27a into REG2
5e 43 42  # Xor above value with REG1
3e 43  # Store value in REG2 to the stack (result of XOR operation)
3a 41 53  # Move top_of_local_stack value into REG0
23 42 25 00 00 00  # Store 0x25 into REG1
2f  # Read from file: nb of bytes read is stored in REG1, filename is on the stack at offset value stored in REG0, content read is stored on stack
3a 41 53  # Move top_of_local_stack value into REG0
24  # Print what has been read from the file
3a 53 46  # Retrieve top_of_local_stack value at the start of the function
29  # Exit function and return to main execution
# Error handling branch (below)
7c 27 00 00 00 43 6f 6e 64 69 74 69 6f 6e 73 20 6e 6f 74 20 6d 65 74 2c 20 6e 6f 74 20 73 68 6f 77 69 6e 67 20 66 6c 61 67 2e 0a 00  # Store on local stack the string "Conditions not met, not showing flag.\n"
3a 41 53  # Move top_of_local_stack value into REG0
24  # Print the string at the offset value stored into REG0
2e  # Exit program

## ask_code FUNCTION
01 08 61 73 6b 5f 63 6f 64 65 02  # ask_code function header
3a 46 53  # Move top_of_local_stack value into REG5 (before strings are stored to the stack)
7c 1e 00 00 00 50 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 73 68 65 6c 6c 63 6f 64 65 3a 20 00  # Store string "Please enter your shellcode: "
3a 41 53 # Move top_of_local_stack value into REG0
24  # Print the string at the offset value stored in REG0
23 42 e8 03 00 00  # Store 0x03e8 into REG1 (length of user input - even if there are no protections against stack overflow)
25  # Wait for user input (our shellcode)
3a 53 46  # Retrieve top_of_local_stack value at the start of the function
29  # Exit function and return to main execution

## MAIN FUNCTION
01 04 6d 61 69 6e 02  # Main function header
28 08 61 73 6b 5f 63 6f 64 65  # Call function ask_code
28 09 73 68 65 6c 6c 63 6f 64 65  # Call function shellcode
28 09 72 65 61 64 5f 66 6c 61 67  # Call function read_flag
5e 41 41 # XOR R0, R0 -> R0 = 0
2e  # Exit program
```

### Main

The `main` function is not that complicated, it calls successively the functions identified above: `ask_code` to retrieve our shellcode, execute our `shellcode` function and then run `read_flag` before exitting.

### ask_code

Let's take a quick look at `ask_code` function even if the name is explicit.

After printing the message "Please enter your shellcode: ", the function waits for an user input and store it on the local stack before exitting.



Even if at the end of the function the stack pointer takes back the value it had before entering the function:
```
3a 46 53
[...]
3a 53 46
29
```

the bytes added onto the stack within `ask_code` function are not erased ! This is why, our shellcode will be found later when called.

### read_flag

The most important function, as there are all the conditions we need to meet in order to get the flag.

By reading instructions, we can write the following pseudo-code :

```python
def read_flag(reg0: int, reg1: int):
	reg2 = reg0
	reg3 = 0x0cd517
	reg0 = reg0 + reg1
	reg0 = reg3 - reg0
	if reg0 != 0:
		print("...error...")
		exit(1)
	reg0 = reg1
	reg3 = 0x1
	reg1 = 0
	while reg0 != 0:
		reg1 = reg1 + reg2
		reg0 = reg0 - reg3

	reg3 = 0xda03833c
	reg0 = reg1
	reg0 = reg0 - reg3
	if reg0 != 0:
		print("...error...")
		exit(1)
	# XOR back filename with reg1 value
	# Read flag from file
	# Print flag
```

I just wrote the code for the conditions we need to meet.

We understand that we must initialize `REG0` and `REG1` correctly in our `shellcode` function in order to meet the conditions.

Now, what values should we put ?

From the first condition, we understand that:

$REG_{0} + REG_{1} = \text{0x0cd517}$ 

Then, we add `REG0` value at the start of the function `REG1` times, as the `while` loop is just a fancy `for` (as `REG3 = 1`). Isn't it the definition of the multiplication ?

The second condition can be written:

$REG_{0}*REG_{1} = \text{0xda03833c}$

Solving this system is equivalent at finding the roots of the polynomial:

$X^{2} - (REG_{0} + REG_{1})X + REG_{0}*REG_{1}$

In other words, we need to solve this equation: 

$X^{2} - (REG_{0} + REG_{1})X + REG_{0}*REG_{1} = 0$

Here is the python script to solve it:

```python
import numpy as np
def parse(elt):
    return hex(int(elt))[2:]
# Solve the system
# R0 + R1 = 0x0cd517
# R0*R1 = 0xda03833c
sol = list(map(parse, np.roots([1, -0x0cd517, 0xda03833c])))
print(sol)
# ['cc403', '1114']
```

We have the values we need to give to `REG0` and `REG1`.

>The problem is symmetric, you can give one value of the other to `REG0`, it won't change anything as the addition and the multiplication are commutative.

# Write the shellcode

First thing to do is having a nice header for our function `shellcode` so it is recognized by the `vm` program !

```python
shellcode_encoded = [hex(ord(c))[2:] for c in "shellcode"]
func_header = "01 09" + "".join(shellcode_encoded) + "02"
```

Nice !

Now, I tried some basic shellcode where I load the values found above in `REG0` and `REG1`, which is done with this instruction: `23 42 14 11 00 00` for `REG1`.

However, there are NULL bytes and whenever I did this, the `ask_code` function didn't read further that the first NULL byte it encounters !

To counter this problem, I needed numbers large enough but still recovering the values needed ! A simple substraction will do ! I took the number `0x12345678` for instance, and computed the other number needed so a `SUB` will give me `0x1114`, which would be: `0x12345678 + 0x1114 = 0x1234678c`.

Do not forget the architecture is little endian !!

The instructions to load those numbers into registers and do the sub operation are:

```bash
23 42 8c 67 34 12 # Load 0x1234678c into REG1
23 43 78 56 34 12 # Load 0x12345678 into REG2
2D 42 43 # Perform REG1 - REG2 and stores it into REG1
```

We can do the same for `REG0` !

`0x12345678 + 0x0cc403 = 0x12411a7b`. Using the same register `REG2`, we get:

```bash
23 41 7b 1a 41 12 # Load 0x12411a7b into REG0
23 43 78 56 34 12 # Load 0x12345678 into REG2
2D 41 43 # Perform REG0 - REG2 and stores it into REG0
```

The final shellcode looks like this:

```bash
23 41 7b 1a 41 12 # Load 0x12411a7b into REG0
23 42 8c 67 34 12 # Load 0x1234678c into REG1
23 43 78 56 34 12 # Load 0x12345678 into REG2
2D 41 43 # Perform REG0 - REG2 and stores it into REG0
2D 42 43 # Perform REG1 - REG2 and stores it into REG1
```

Finally, we need to exit the function and return to `main` execution, with a simple `29` bytecode.

Here is my final script:

```python
import binascii
import numpy as np
from pwn import remote

shellcode_encoded = [hex(ord(c))[2:] for c in "shellcode"]

func_header = "01 09" + "".join(shellcode_encoded) + "02"
end = "3A 53 46 29 65 00 0A"

def parse(elt):
    return hex(int(elt))[2:]
# Solve the system
# R0 + R1 = 0x0cd517
# R0*R1 = 0xda03833c
sol = list(map(parse, np.roots([1, -0x0cd517, 0xda03833c])))
# print(sol)
# ['cc403', '1114']

# We cannot send null byte, thus, I do substractions to obtain the values
# above
load = "23 41 7b1a4112 23 42 8c673412 23 43 78563412"
sub = "2D 41 43 2D 42 43"

shellcode = func_header + "3A 46 53" + load + sub + end

shellcode = shellcode.replace(" ", "")

# Local
# f = open("shellcode.vmr", "wb")
# f.write(binascii.unhexlify(shellcode))
# f.close()

# remote
HOST = "challenges.404ctf.fr"
PORT = 31008

r = remote(HOST, PORT)

data = r.recvuntil(b"")
print(data.decode())

r.sendline(binascii.unhexlify(shellcode))

flag = r.recvuntil(b"}")
print(flag)

# Flag 404CTF{Y0u_C4n_Wr1t3_PR0graM5_:pog:}
```

In my script, I blindly followed what I saw in the other functions from `shellcode_my_vm_redacted.vmr`, and I added the handling of `top_of_local_stack` with the instructions: `3A 46 53 [...] 3A 53 46 29`. Yet, I believe it works without them as we don't add anything on the stack.

A last remark, in these instructions `end = "3A 53 46 29 65 00 0A"`, I added some junk data after the `29` bytecode because I wanted to be sure it was read x). I guess it works without it !

Thanks for the challenge, it was very fun !
