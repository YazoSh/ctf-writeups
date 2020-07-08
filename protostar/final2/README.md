## Protostar final2 writeup

This is my first writeup so i hope it's not too messy or hard to understand

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
