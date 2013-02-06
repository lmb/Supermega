Supermega API
=============

supermega.Session
-----------------

*C->S*
ug?, us!, (usl), uq?

*S->C*
k

Performs initial authentication against the MEGA servers, caches auth credentials and
centrally stores sid/nid as well as sequence IDs.

This class also polls the MEGA server for new events, and distributes them accordingly. (TODO)

supermega.User (not exposed)
--------------
Stores meta information on a given user.

* Public key
* Master key
* Derived key (from password)

supermega.Meta / File / Directory (not exposed)
--------------

*C->S*
f, p?, d, m, a, l, s, k, g?, u?

*S->C*
t, d, s

Stores meta information about a particular node. This is essentially the API's single
model (for now). Nodes form a tree, and MEGA exposes three trees as of now: CloudDrive,
Inbox, Trash.

A node can represent:
* A directory (with subnodes)
* A file (with file contents)
* A special node (root, inbox, trash)

File upload could be handled from this class, depending on MEGA API requirements.

_Questions:_

* Can non-leaf nodes contain file data?

supermega.Contents (part of models.File)
--------------
Handles de/encryption as well as verificiation of file contents. There are two possible
usage scenarios:

1. Used with an unencrypted file on the local filesystem / on a remote location, creates
   an encrypted one in a local cache. (TODO)
2. Used with an encrypted file stored in a local cache, creates an unencrypted one.

_Encrypting a file:_ (TODO)

1. Generate symmetric encryption key and setup crypto
2. Split stream into chunks
3. Iterate over file chunks
   1. Encrypt chunk
   2. Calculate CBC-MAC of encrypted chunk
   3. Store MAC
   4. Upload encrypted data
3. Calculate meta MAC

_Decrypting a file:_

1. Obtain necessary crypto secrets and IVs
2. Iterate over file chunks
   1. Decrypt chunk
   2. Verify chunk integrity
   3. Write to stream

supermega.Request (private)
---------------------------
Handles a single request. Needs a supermega.Session for user credentials and a sequence
number. If a request fails it is automatically retried using exponential back-off.
Returns a response object, that might indicate errors or supplies response data.

supermega.Response (private)
----------------------------
Handles mixed error code / json responses for a request. Takes a requests.response object.