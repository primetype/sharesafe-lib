-- |
-- Module      : Prime.Secret
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Secret
    ( -- * Keys
      PublicKey
    , PrivateKey
    , KeyPair(..)
    , keyPairGenerate
    , -- * Salt
      Salt
    , mkSalt
    , -- * Passwords
      Password
    , PasswordProtected
    , protect
    , recover
    , -- * Signing
      Signature
    , SigningKey
    , VerifyKey
    , toVerifyKey
    , sign
    , verify
    , signingKeyFromPassword
    , -- * Secret
      Share(..), ExtraGen, Commitment, EncryptedShare, DecryptedShare, Threshold
      -- ** generate secret
    , generateSecret
      -- ** verify share
    , verifyShare
      -- ** recove share
    , recoverShare
      -- ** recove Secret
    , recoverSecret
    , -- * Ciphering
      -- ** Keys
      EncryptionKey
    , encryptionKey
    , generateEncryptionKey
    ,  -- ** stream
      State
    , start
    , mkNonce, Nonce
    , finalize, Auth
    , encrypt, encryptC, encryptC'
    , decrypt, decryptC, decryptC'
    , -- ** helpers
      Ciphered(..)
    , encrypt'
    , decrypt'
    , -- * Random
      MonadRandom(..)
    , -- * Error
      CryptoFailable(..)
    , CryptoError(..)
    , throwCryptoError
    , throwCryptoErrorIO
    ) where

import Prime.Secret.Cipher
import Prime.Secret.Client
import Prime.Secret.Keys
import Prime.Secret.Password
import Prime.Secret.Signing

import Crypto.Random
import Crypto.Error
