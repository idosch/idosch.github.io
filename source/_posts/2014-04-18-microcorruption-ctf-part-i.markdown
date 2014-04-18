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

First level: New Orleans
------------------------
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
