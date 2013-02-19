Supermega - MEGA.co.nz API client
=================================

I was intrigued by MEGA's API, and decided to write a client library for it. In the process I completely overengineered it, which is fine. If you find any gremlins / bugs in the code, please open an issue.

What does it do right now?
--------------------------

It pretty much does what all the other python MEGA.co.nz clients do (there are two I know of):

* Lets you login (your account, ephemeral, from environment)
* Inspect the contents of your account
* Download public files
* Upload / download / move / delete of your own files, create public links

Why should I use it over XYZ?
-----------------------------

Supermega goes through more effort than the other client libs. Requests to and from the MEGA servers are validated against a schema, and as little as possible of the wheel is reinvented when it comes to cryptography. That is usually a good thing.

Usage
-----

### Login

```python
from supermega import Session

sess = Session()
sess.login('user@example.org', 'password')
# or
sess = Session('user@example.org', 'password')

# ephemeral account
sess.ephemeral()

# from MEGA_USERNAME and MEGA_PASSWORD env vars
sess = Session.from_env()
```

### Upload

```python
from supermega import Session, File

sess = ...

# Upload a regular file
with open('/path/to/file', 'rb') as handle:
    # First argument is the directory the file is uploaded to
    file = File.upload(sess.root, handle, 'filename.txt')
    # or (doesn't make much sense though)
    file = File.upload(sess.trash, handle, 'filename.txt')

    print file.get_public_url()

# Upload from another MEGA file, even from an other account
file = ... # See below
new_file = File.upload(sess.root, file)
```

### Download

From a public url:

```python
from supermega import Session

# Downloads into current working dir
Session.download_to_file('https://your/mega/url')

# Downloads into file-like object
with open('../other/dir/filename.ext', 'wb') as handle:
    Session.download_to_file('https://your/mega/url', handle)

# Provide your own download handler
def to_disk(file, chunks):
    with open(file.name, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)

Session.download(to_disk, 'https://your/mega/url')
```

A file in your MEGA account:

```python
from supermega import Session

# login, etc.

file = ... # See 'Listing / finding files'

sess.download_to_file(file)
# or
def to_disk(...):
    # See above

file.download(to_disk)
# or
sess.download(to_disk, file)
```

### Listing / finding files

```python

from supermega import Session

# login, etc.

sess.root.print_tree()
sess.trash.print_tree()

# lookup by filename (this is not recursive)
file = sess.root['filename.txt']

# lookup by file handle
file = sess.datastore['handle']
```

### Other file operations

```python
from supermega import Session

# login
sess = ...

# get hold of a file object
file = ...

# This does not delete a file but merely moves it into the "Trash" folder
file.move_to(sess.trash)

# This deletes a file, which does not have to be in the trash
file.delete()
```

Installation
------------

Should be as easy as doing a `pip install git+git://github.com/lmb/Supermega.git#egg=supermega`. The dependencies might be messed up, please let me know.

How is it organized?
--------------------

* supermega.errors: exceptions
* supermega.protocol: defines the JSON requests / responses MEGA expects and has a somewhat decent interface to run them
* supermega.transport: some low level stuff that actually dispatches requests to the servers
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
