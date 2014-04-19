---
layout: post
title: "Microcorruption CTF - Part I"
date: 2014-04-18 23:29:17 +0300
comments: false
categories: 
---

Introduction
------------
[Microcorruption CTF](https://microcorruption.com) (or uctf) is a security challenge in which you are given an electronic lock (Lockit all LockIT Pro) based on the [TI MSP430](http://en.wikipedia.org/wiki/TI_MSP430) microcontroller and a debugger connected to it. The objective is to find inputs that will unlock the device in order to allow access to your operatives scattered around the world into different warehouses. The device even has his own bogus [manual](https://microcorruption.com/manual.pdf) which is a must read.

In this post I will write and explain my solutions to the various levels of the challenge. Please note that I did not try to optimize my solution - that is, there are solution with shorter input and which use less CPU cycles. In the future I might update this post with more elegant solutions.

Level 1: New Orleans
--------------------
The interesting part is the `check_password` subroutine located at 0x44bc:
```
44bc <check_password>
44bc:  0e43           clr   r14
44be:  0d4f           mov   r15, r13
44c0:  0d5e           add   r14, r13
44c2:  ee9d 0024      cmp.b @r13, 0x2400(r14)
44c6:  0520           jne   #0x44d2 <check_password+0x16>
44c8:  1e53           inc   r14
44ca:  3e92           cmp   #0x8, r14
44cc:  f823           jne   #0x44be <check_password+0x2>
44ce:  1f43           mov   #0x1, r15
44d0:  3041           ret
44d2:  0f43           clr   r15
44d4:  3041           ret
```
Lines 0x44be through 0x44cc form a loop which is executed eight times, at each iteration checking whether the byte in memory location pointed to by `r13` (your password) is in accordance with the authorized password (at memory location `0x2400+r14`). Therefore, the password is `?qa0+]P`.

Level 2: Sydney
---------------
As in the previous level, the interesting part here is also the `check_password` subroutine:
```
448a <check_password>
448a:  bf90 435d 0000 cmp   #0x5d43, 0x0(r15)
4490:  0d20           jnz   $+0x1c
4492:  bf90 3f53 0200 cmp   #0x533f, 0x2(r15)
4498:  0920           jnz   $+0x14
449a:  bf90 5f3e 0400 cmp   #0x3e5f, 0x4(r15)
44a0:  0520           jne   #0x44ac <check_password+0x22>
44a2:  1e43           mov   #0x1, r14
44a4:  bf90 4241 0600 cmp   #0x4142, 0x6(r15)
44aa:  0124           jeq   #0x44ae <check_password+0x24>
44ac:  0e43           clr   r14
44ae:  0f4e           mov   r14, r15
44b0:  3041           ret
```
A pointer to the entered password is passed to the subroutine via r15. Each of the four `cmp` instructions checks whether the two bytes pointed to by `r15` plus the offset is valid. Notice that here - unlike in the previous level - the `cmp` instruction is used and not `cmp.b`. The word size in the MSP430 is 16 bits and therefore the instructions operate on two bytes of data unless specifically told to do otherwise (by using a `.b` suffix).

Since the MSP430 is [little-endian](http://en.wikipedia.org/wiki/Endianness) multi-byte values are stored in memory in reverse order. Thus, the password is `0x435d3f535f3e4241`.

Level 3: Hanoi
--------------
Instead of of using the lock itself to test the entered password, here Hardware Security Module 1 (HSM 1) is used. Using the interrupt `0x7d` (refer to the user manual for more details) the microcontroller can test if the entered password is valid. Therefore, unlike previous levels, in this level it is not possible to extract the password from the given code. Looking at the `login` subroutine we can see that the following happens:

1. `getsn` is used to retrieve a password of length up to `0x1c` bytes from the user into memory starting at address `0x2400`.
2. `test_password_valid` is called with address `0x2400` as an argument.
3. Access is granted by calling `unlock_door` if address `0x2410` stores the value `0x2d`.
```
4520 <login>
4520:  c243 1024      mov.b #0x0, &0x2410
4524:  3f40 7e44      mov   #0x447e "Enter the password to continue.", r15
4528:  b012 de45      call  #0x45de <puts>
452c:  3f40 9e44      mov   #0x449e "Remember: passwords are between 8 and 16 characters.", r15
4530:  b012 de45      call  #0x45de <puts>
4534:  3e40 1c00      mov   #0x1c, r14
4538:  3f40 0024      mov   #0x2400, r15
453c:  b012 ce45      call  #0x45ce <getsn>
4540:  3f40 0024      mov   #0x2400, r15
4544:  b012 5444      call  #0x4454 <test_password_valid>
4548:  0f93           tst   r15
454a:  0324           jz    $+0x8
454c:  f240 d400 1024 mov.b #0xd4, &0x2410
4552:  3f40 d344      mov   #0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call  #0x45de <puts>
455a:  f290 2d00 1024 cmp.b #0x2d, &0x2410
4560:  0720           jne   #0x4570 <login+0x50>
4562:  3f40 f144      mov   #0x44f1 "Access granted.", r15
4566:  b012 de45      call  #0x45de <puts>
456a:  b012 4844      call  #0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov   #0x4501 "That password is not correct.", r15
4574:  b012 de45      call  #0x45de <puts>
4578:  3041           ret
```
Although the user is prompt to enter a password of up to 16 bytes there is no input checking. Therefore, by entering a 17 chars password with the last one set to `0x2d` it is possible to overwrite memory address `0x2410` and trick the program. A good password is thus: `0x414141414141414141414141414141412d`.

Level 4: Cusco
--------------
This one is a classic [stack smashing](http://en.wikipedia.org/wiki/Stack_buffer_overflow) level. I won't get into the whole "how the stack works" since there are [great](http://duartes.org/gustavo/blog/post/journey-to-the-stack/) [resources](http://duartes.org/gustavo/blog/post/epilogues-canaries-buffer-overflows/) covering it already, but only explain the general idea bellow. The `login` subroutine does the following:

1. Read up to `0x30` chars from the user into the stack.
2. Test whether the entered password is valid by sending the password location as an argument to `test_password_valid`.
3. Unlock the door via `unlock_door` if the password is valid.

```
4500 <login>
4500:  3150 f0ff      add   #0xfff0, sp
4504:  3f40 7c44      mov   #0x447c "Enter the password to continue.", r15
4508:  b012 a645      call  #0x45a6 <puts>
450c:  3f40 9c44      mov   #0x449c "Remember: passwords are between 8 and 16 characters.", r15
4510:  b012 a645      call  #0x45a6 <puts>
4514:  3e40 3000      mov   #0x30, r14
4518:  0f41           mov   sp, r15
451a:  b012 9645      call  #0x4596 <getsn>
451e:  0f41           mov   sp, r15
4520:  b012 5244      call  #0x4452 <test_password_valid>
4524:  0f93           tst   r15
4526:  0524           jz    #0x4532 <login+0x32>
4528:  b012 4644      call  #0x4446 <unlock_door>
452c:  3f40 d144      mov   #0x44d1 "Access granted.", r15
4530:  023c           jmp   #0x4536 <login+0x36>
4532:  3f40 e144      mov   #0x44e1 "That password is not correct.", r15
4536:  b012 a645      call  #0x45a6 <puts>
453a:  3150 1000      add   #0x10, sp
453e:  3041           ret
```

The user is prompt to enter a password between 8 and 16 chars (although, as you have probably noticed, it is not forced). Entering `idosch1234`, putting a breakpoint at `0x453e` (just before `login` returns) and examining the stack we see the following (the stack pointer points to `0x43fe`):

```
break 453e
```

```
43d0:   0000 0000 0000 0000 0000 0000 5645 0100   ............VE..
43e0:   5645 0300 ca45 0000 0a00 0000 3a45 6964   VE...E......:Eid
43f0:   6f73 6368 3132 3334 0000 0000 0000 3c44   osch1234.......D
```

Visible are:

1. Leftovers from previous [stack frames](http://en.wikipedia.org/wiki/Call_stack) (in lower addresses).
2. The entered password in the current stack frame and the address to return to after the `login` subroutine ends: `0x443c`.

By entering a 18 bytes password we can effectively take control of the program execution and make it return to wherever we want. A good place is the `unlock_door` subroutine located at memory address `0x4446`. Entering the password `0x414141414141414141414141414141414644` does the trick.

Level 5: Reykjavik
------------------
At first this level seems very weird as there are no calls to the usual I/O subroutines `getsn` and `puts`. However, looking at `main`, visible is a call to a subroutine starting at address `0x2400`:

```
4438 <main>
4438:  3e40 2045      mov   #0x4520, r14
443c:  0f4e           mov   r14, r15
443e:  3e40 f800      mov   #0xf8, r14
4442:  3f40 0024      mov   #0x2400, r15
4446:  b012 8644      call  #0x4486 <enc>
444a:  b012 0024      call  #0x2400
444e:  0f43           clr   r15
```

Using the disassembler the following code reveals itself:
```
push r11
push r4
mov  sp, r4
add  #0x4, r4
add  #0xffe0, sp
mov  #0x4520, r11
jmp  $+0x10
inc  r11
sxt  r15
push r15
push #0x0
call #0x2464
add  #0x4, sp
mov.b    @r11, r15
tst.b    r15
jnz  $-0x12
push #0xa
push #0x0
call #0x2464
add  #0x4, sp
push #0x1f
mov  #0xffdc, r15
add  r4, r15
push r15
push #0x2
call #0x2464
add  #0x6, sp
cmp  #0xadf2, -0x24(r4)
jnz  $+0xc
push #0x7f
call #0x2464
incd sp
add  #0x20, sp
pop  r4
pop  r11
ret
mov  0x2(sp), r14
push sr
mov  r14, r15
swpb r15
mov  r15, sr
bis  #0x8000, sr
call #0x10
pop  sr
ret
call &0x9a18
bis  @r12, sr
bit.b    r9, r5
subc.b   r9, sr
add  @r5, r13
sub  r14, -0x5d5c(r5)
bis.b    @r7, r7
dadd 0x19a1(r14), r4
and.b    @r6+, r6
bic.b    r11, sr
rrc  -0x5f2(r12)
invalid  @r6
dadd.b   @r7+, r4
addc.b   r11, sp
jge  $-0x5a
incd &0xe422
dadd.b   @r15, r6
dadd.b   r5, -0x746d(sp)
subc sp, -0x7765(r9)
cmp.b    @r11+, 0x7466(r10)
jnz  $+0x29e
addc @r11, r10
mov  #-0x1, 0x5191(sp)
bic  @r12+, r13
and  @r5, -0x5826(r6)
jmp  $-0x48
jmp  $+0x11c
rrc.b    r13
jge  $-0x370
dadd.b   -0x65bb(r6), 0x6124(r15)
sxt  &0x9132
xor  0x5781(r6), r4
and  @r14+, -0x22d3(pc)
reti pc
sub  r8, 0x1063(r6)
bit  #-0x1, r10
jnc  $-0x13c
bis  r9, r11
jmp  $-0x16e
rrc.b    r14
subc.b   0x384c(pc), r8
jmp  $+0x194
jge  $-0x200
rra  r14
jmp  $-0x300
add.b    @r5+, -0x1052(r10)
rrc  r5
jc   $+0x4a
add  @r6+, r12
dadd 0x7be5(r15), 4
bit  r15, 0x4030(r10)
jge  $-0x74
addc.b   @r14, r5
subc r8, &0xf99a
call -0x7c42(r13)
sub  @r12+, 8
bis  @r8+, r10
add  @r10+, r9
xor.b    #-0x1, 0x34f(r12)
bic  r9, -0x6a6d(r14)
rra.b    r10
jl   $-0x62
call @r13+
subc.b   @r9+, r7
bic.b    #0x0, -0xda1(r9)
bic  @r7+, r13
add.b    #0x1, r9
jz   $-0x2ee
bit.b    -0x727(r5), -0x619d(pc)
subc.b   @pc, -0x32ff(r9)
rra  @sp
addc.b   r10, 0x2cd1(r10)
xor  &0x3875, -0x3a6a(r7)
jnc  $+0x120
sub.b    &0xe51b, 0x20ab(r6)
sub.b    @r9+, 4
dadd.b   r10, r8
dinc r15
jc   $-0x170
addc @r4, 0x2dde(r5)
swpb @r7+
sub  0x552(sp), 0x448d(pc)
and.b    r4, 0x2ebc(r15)
subc.b   -0xb2b(r10), r7
add  @sp, 0x43c2(r8)
subc @r13, r7
bic  @r10, 0x6b1e(r4)
```

This is quite a clusterfuck, but pretty quickly it becomes evident that the INT subroutine (the one used to interface with the HSMs and the deadbolt) is at `0x2464` (line 37). The interesting part is at `0x2450` (line 31) where the INT subroutine is called with `0x7F` as an argument:

```
...
cmp  #0xadf2, -0x24(r4)
jnz  $+0xc
push #0x7f
call #0x2464
...
```

Looking at the user manual one can see that this interrupt is used to interface with the deadbolt and trigger an unlock. In order to reach this line the value at memory location `@r4-0x24` needs to be `f2ad`. Using the debugger, this memory location turns out to be the start of the entered password. Therefore, the password is: `0xf2ad`.
