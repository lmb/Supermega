Supermega - MEGA.co.nz API client
=================================

I was intrigued by MEGA's API, and decided to write a client library for it. In the process I completely overengineered it, which is fine. If you find any gremlins / bugs in the code, please open an issue.

What does it do right now?
--------------------------

It pretty much does what all the other python MEGA.co.nz clients do (there are two I know of):

* Lets you login
* Lets you use an ephemeral account
* Gives you a list of files / directories to iterate over
* Lets you download a public file
* Upload / download / move / delete of your own files

Why should I use it over XYZ?
-----------------------------

Supermega goes through more effort than the other client libs. Requests to and from the MEGA servers are validated against a schema, and as little as possible of the wheel is reinvented when it comes to cryptography. That is usually a good thing.

Examples
--------

_Neat stuff:_
y
```python
import supermega

s1 = supermega.Session()
s1.login('user1@example.org', 'pass1')
s1.init_datastore()

s2 = supermega.Session()
s2.login('user2@example.org', 'pass2')
s2.init_datastore()

source_file = s2.datastore['FILE_ID'] # Try iterating s2.datastore.root.walk()
new_file_on_s1 = supermega.File.upload(s1.datastore.root, source_file)
```

Source file from account 2 is now on account 1 (this of course involves downloading the file from account 2 first).

_Download a file:_

```python
import supermega

def to_disk(file, chunks):
    with open(file.name, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)

s = supermega.Session()
s.login('user@example.org', 'password')
s.download(to_disk, 'https://mega.co.nz/#!FILE_URL')
```

_Download a file into the current working directory:_

```python
import supermega

s = supermega.Session()
s.download_to_file('PUBLIC_URL')
```

_Download a file into an arbitrary file-like object:_
```python
import supermega

s = supermega.Session()
with open('FILENAME', 'wb') as f:
    s.download_to_file('PUBLIC_URL', f)
```

_List files:_

```python
import supermega

s = supermega.Session()
s.login('user@example.org', 'password')

s.init_datastore()
for parent, subdirs, files in s.datastore.root.walk():
    print "-----------------------"
    print "For: {}".format(parent)
    print "Subdirs:"
    for subdir in subdirs:
        print subdir

    print
    print "Files:"
    for f in files:
        print f
```

You can use the file objects as arguments to the Session.download* functions, although this only makes sense if you're logged in.

Installing
----------

Should be as easy as doing a `pip install git+git://github.com/lmb/Supermega.git#egg=supermega`. The dependencies might be messed up, please let me know.

How is it organized?
--------------------

* supermega.models: handles crypto stuff
* supermega.errors: exceptions
* supermega.protocol: defines the JSON requests / responses MEGA expects and has a somewhat decent interface to run them
* supermega.transport: some low level stuff that actually dispatches requests to the servers.
* supermega.utils: stuff that probably should be somewhere else

Interesting stuff
-----------------
Julien Marchand has some blog posts up that explain the MEGA API in more detail:

1. [Basic API](http://julien-marchand.fr/blog/using-mega-api-with-python-examples/)
2. [Download a public file](http://julien-marchand.fr/blog/using-the-mega-api-how-to-download-a-public-file-or-a-file-you-know-the-key-without-logging-in/)

So how secure are my files?
---------------------------

Since I'm not a cryptographer I have no idea. A few points to note though:

* MEGA does not use best-practises for public key crypto. Specifically I think that they aren't using one of the well-tested padding schemes.
* There are an awful lot of zero IVs involved in the API.
