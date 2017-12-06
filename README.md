[![Linux Build Status](https://img.shields.io/travis/primetype/sharesafe-lib/master.svg?label=Linux%20build)](https://travis-ci.org/primetype/sharesafe-lib)
[![BSD3](https://img.shields.io/badge/License-BSD-blue.svg)](https://en.wikipedia.org/wiki/BSD_License)
[![Haskell](https://img.shields.io/badge/Language-Haskell-yellowgreen.svg)](https://www.haskell.org)

# sharesafe

**ShareSafe** is an open source library and command line tool to leverage
[`PVSS` (Publicly Verifiable Secret Sharing)](https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing).

The main idea is to facilitate the exchange of sensible data between parties.
For example, one of the main application of the command line tool provided
in this repository is to share deployment keys and configuration between the
devops.

# Usage Examples

## Threshold of 1

The threshold is the minimum amount of participant that needs to work together
to retrieve a shared secret. Below is an example of usage with a threshold of
1: i.e. any participant can retrieve the secret independently from each other.

Having a threshold of 1 allows:

* sending end-to-end encrypted messages. All that needs to be known is the
  recipient's public key;
* storing sensitive information on a shared repository (config files, ssh keys,
  etc).

### Sharing Deployment Files on repositories

Let's say we are all sensible developers and that we all use git and github
to host our projects: product source code, deployment scripts etc.

Often the developers are also the one who will need to `ssh` on the production
server and make the deployment/migration. How would they share the _ssh keys_
and the deployment configuration files?

We could use one of the many archivers or `gpg` and set a password to the files.
Then we can send the password by email, text, slack to the people who need to
know.

The issue is that we are still trusting the email provider or the messaging app.

This is where **PVSS** comes to help us. We can avoid sharing the password.

Let say we have 3 user working on the same repository. 2 of them needs to share
sensible files for deployments.

**User1** and **User2** generates their respective key pairs and they use
the public keys (`PK1` and `PK2`) to create a shared secret (here, a Symmetric
Encryption key `Secret`) and their respective share of the secret.

**User1** will need to use its Secret Key (`SK1`) to unlock its share of the
secret and then retrieve the `Secret` (here, the Symmetric Encryption Key).


```
+-----------------------------+
|                             |
|                             |
|          +---------------+  |   +---------------+      +---------------+
|          |               |  |   |               |      |               |
|          | User1         |  |   | User2         |      | User3         |
|          |               |  |   |               |      |               |
|          |               |  |   |               |      |               |
|          |  +----------+ |  |   |  +----------+ |      |               |
|          |  |          | |  |   |  |          | |      |               |
+-------------+ PK1      | |  +------+ PK2      | |      |               |
|          |  +----------+ |      |  +----------+ |      |               |
|          |  +----------+ |      |  +----------+ |      |               |
|          |  |          | |      |  |          | |      |               |
|          |  |SK1       | |      |  |SK2       | |      |               |
|          |  +----+-----+ |      |  +---+------+ |      |               |
|          +------ | ------+      +----- | -------+      +---------------+
|                  |                     |
|                  |                     |
|Create secret     |                     |
|from Public       |Unlock               |Unlock
|Keys              |share                |Share
|                  |                     |
|      +---------- | ------------------- | ------------+
|      | +---------v----------+ +--------v-----------+ |
|      | |                    | |                    | |
|      | |User1 Share         | | User2 Share        | |
|      | |of the Secret       | | of the Secret      | |
+------+ |                    | |                    | |
       | +--+-----------------+ +--------------+-----+ |
       |    |   +-------------------------+    |       |
       |    |   |                         |    |       |
       |    +--->  Secret                 <----+       |
       |        +----------------+--------+            |
       +------------------------ |  -------------------+
                                 |
                                 +----+---------------+Symmetric
                                      |               |Encryption
            +------------------------ |  -----------  |  -----------------+
            |                         |               |                   |
            | Project             +---v-----+    +----v-----+             |
            | repository          |         |    |          |             |
            |                     | Deploy  |    | Deploy   |             |
            |                     | ment    |    | ment     |             |
            |                     | Key     |    | Config   |             |
            |                     |         |    |          |             |
            |                     +---------+    +----------+             |
            +-------------------------------------------------------------+
```

## Threshold of 2 or more

Using a threshold greater than one requires some participants to work together
(and therefore to agree together) to unlock a secret.

* we could think of shared bank account where all or at least some of the owners
  need to agree to make transactions;
* opening the will of a defunct;
* [electronic voting (link to a PDF)](http://www.win.tue.nl/~berry/papers/crypto99.pdf)
