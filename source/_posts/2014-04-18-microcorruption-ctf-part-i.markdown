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

Since the MSP430 is [little-endian](http://en.wikipedia.org/wiki/Endianness) multi-byte values are stored in memory in reverse order. Thus, the password is `435d3f535f3e4241`.

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
Although the user is prompt to enter a password of up to 16 bytes there is no input checking. Therefore, by entering a 17 chars password with the last one set to `0x2d` it is possible to overwrite memory address `0x2410` and trick the program. A good password is thus: `414141414141414141414141414141412d`
