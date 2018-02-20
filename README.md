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

## TL;DR: how to quickly start using `sharesafe`

### Installation

The recommended way is to use [`stack`](https://haskell-lang.org/get-started).

```shell
git clone https://github.com/primetype/sharesafe-lib
cd sharesafe-lib
stack install sharesafe
```

### grand tour

#### creating key pairs

The first thing you need to start sharing secrets is to generate key pairs:

```shell
# create a password protected secret key and public key
sharesafe key new --password "c-137" --output rick.key
sharesafe key new --password "Jessica" --output morty.key
sharesafe key new --output jerry.key # no password... risky...
# export your public key into a separate file
sharesafe key export-public --input rick.key --output rick.pub
```

#### Kitchen Sink command

Now that you can create key: you can create share package.

```shell
# encrypt a file and store all the details to retrieve the secret in the
# metadata of the output. You can set the public key or the key pair (only
# the public key is necessary):
sharesafe encrypt --participant rick.pub -p morty.key -p jerry.pub -t 2 -i citadel.blueprint -o secret.sharepkg

# decrypt a sharepkg is easy. We need the keypair here. The password to unlock
# the private key will be asked without echoing to the terminal.
sharesafe decrypt -p rick.key -p morty.key -i secret.sharepkg -o citadel.blueprint
rick password: ******
morty password: ********
```

### Advanced

#### create a secret

to create a secret, you only need the participants' _public key_. **There is
no need for the private keys nor the passwords**.

```shell
sharesafe pvss new --secret encryption.key --threshold 2 --participant rick.pub  --participant morty.pub --participant jerry.pub
```

This command will create:

* a share secret and will convert it into a **ChaChaPoly1305** compatible encryption key `encryption.key` (see below);
* for every participant a `.secret-share` file is created:
  * `rick.secret-share`: rick's share, encrypted with its public key (only rick's private key can unlock the share);
  * `morty.secret-share`: morty's share, encrypted with its public key (only morty's private key can unlock the share);
  * `jerry.secret-share`: jerry's share, encrypted with its public key (only jerry's private key can unlock the share);

> the `.secret-share` files can safely be shared over any support, secured or not.
> They are encrypted a way only the owner of the private key can open it.

In this command, the `threshold` is the minimum number of _opened shares_ needed
to recover the `encryption.key`. See next command.

#### Recover a secret

To recover a shared secret, we need _n_ participants (`threshold`) to open
their `.secret-share`.

```shell
sharesafe pvss reveal-share -share rick.secret-share --key rick.key --password "c-137" -o rick.revealed-share
```

In the example above we set the threshold to 2 participants, so to retrieve the
secret (`encryption.key`):

```shell
sharesafe pvss recover --share rick.revealed-share --share morty.revealed-share -o encryption.key
```

#### Use the generated/recovered to encrypt or decrypt a file

`sharesafe` provides builtin support for ChaChaPoly1305 encryption protocol.
This is a symmetric encryption. So the key is used for both encryption and
decryption.

```shell
sharesafe cipher encrypt --key encryption.key --input destroying_the_citadel.pdf --output shielded_document
sharesafe cipher decrypt --key encryption.key --input shielded_document          --output destroying_the_citadel.recovered.pdf
```

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
