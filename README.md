Supermega - MEGA.co.nz API client
=================================

I was intrigued by MEGA's API, and decided to write a client library for it. In the process I completely overengineered it, which is fine. If you find any gremlins / bugs in the code, please open an issue.

What does it do right now?
--------------------------

It pretty much does what all the other python MEGA.co.nz clients do (there are two I know of):

* Lets you login
* Gives you a list of files / directories (no names yet) to iterate over
* Lets you download one of your own files
* Should let you download a public file (this isn't tested too much)

Right now it doesn't support ephemeral user accounts, sorry.

Why should I use it over XYZ?
-----------------------------

Supermega goes through more effort than the other client libs. Requests to and from the MEGA servers are validated against a schema, and as little as possible of the wheel is reinvented when it comes to cryptography. That is usually a good thing.

Example
-------

_Download a file:_

    import supermega

    def to_disk(file, chunks):
        with open(file.name, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)

    s = supermega.Session()
    s.login('user@example.org', 'password')
    s.download(to_disk, 'https://mega.co.nz/#!FILE_URL')

_List files:_

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
