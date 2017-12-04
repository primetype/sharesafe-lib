-- |
-- Module      : Prime.Secret.Password
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
-- # Protect data with Password
--
-- Using PBKDF2/SHA512 + ChaChaPoly1305
--
-- Wrapped up data With `PasswordProtected` tag so we know if it is safe
-- to store and share it or not
--
-- ```
-- let secret = "my secret"
-- let password = "my password"
-- password_protected_secret <- throwCryptoError <$> protect password secret
-- print protected_secret
-- let retrieved_secret = throwCryptoError $ recover password password_protected_secret
-- print retrieved_secret
-- ```
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}

module Prime.Secret.Password
    ( Password
    , PasswordProtected
    , protect
    , recover
    , Salt
    , mkSalt
    ) where

import qualified Prelude

import Prime.Common.Base
import Prime.Common.JSON
import Prime.Common.Persistent
import Prime.Common.PEM

import Servant.Docs

import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import           Crypto.Random (MonadRandom(..))
import           Crypto.Error

import Crypto.KDF.PBKDF2 (fastPBKDF2_SHA512, Parameters(..))
import Data.ByteString.Char8 (unpack)

import Prime.Secret.Cipher

-- | Password, not showable, should not be serialised etc.
--
-- The memory is scrubbed so it is not possible to recover it later
--
newtype Password = Password B.ScrubbedBytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Show Password where
    show = unpack . B.convert
instance ToSample Password where
    toSamples _ = singleSample $ B.convert ("correct-horse-battery-staple" :: String)
instance ToJSON Password where
    toJSON = toJSON . Base64
instance FromJSON Password where
    parseJSON a = unBase64 <$> parseJSON a
instance Arbitrary Password where
    arbitrary = elements $ nonEmpty_ $ fmap B.convert
      [ mempty :: String
      , "correct-host-battery-staple" :: String
      ]

newtype Salt = Salt B.Bytes
    deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Show Salt where
    show = unpack . B.convertToBase B.Base64
instance ToJSON Salt where
    toJSON = toJSON . Base64
instance FromJSON Salt where
    parseJSON a = unBase64 <$> parseJSON a
instance ToSample Salt where
    toSamples _ = singleSample $ B.convert ("\0\1\2\3\4\5\6\7\8\9\10\11" :: String)
instance Arbitrary Salt where
    arbitrary = liftCryptoRandom mkSalt

defaultSaltLength :: Int
defaultSaltLength = 12

mkSalt :: MonadRandom randomly => randomly Salt
mkSalt = getRandomBytes defaultSaltLength

defaultParameters :: Parameters
defaultParameters = Parameters
    { iterCounts    = 4000
    , outputLength  = 32
    }

-- | protect the given bytes with a password
protect :: (MonadRandom randomly, ByteArrayAccess bytes)
        => Password
        -> bytes
        -> randomly (CryptoFailable (PasswordProtected bytes))
protect pwd stuff = do
    let header = mempty :: B.ScrubbedBytes
    Salt salt <- mkSalt

    case encryptionKey $ fastPBKDF2_SHA512 defaultParameters pwd salt of
        CryptoFailed err -> return $ CryptoFailed err
        CryptoPassed pps -> do
            rf <- encrypt' pps header (B.convert stuff :: B.Bytes)
            return $ do
                Ciphered r <- rf
                return $ PasswordProtected $ salt <> r

-- | recover the given PasswordProtected bytes
recover :: ByteArray bytes
        => Password
        -> PasswordProtected a
        -> CryptoFailable bytes
recover pwd (PasswordProtected salt_stuff) = do
    let header = mempty :: B.ScrubbedBytes
    let salt = B.view salt_stuff 0 defaultSaltLength
    let stuff = Ciphered $ B.drop  defaultSaltLength salt_stuff
    pps <- encryptionKey $ fastPBKDF2_SHA512 defaultParameters pwd salt
    decrypt' pps header stuff

newtype PasswordProtected a = PasswordProtected B.Bytes
  deriving (Show, Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ToJSON (PasswordProtected a) where
    toJSON = toJSON . Base64
instance FromJSON (PasswordProtected a) where
    parseJSON a = unBase64 <$> parseJSON a
instance PersistField (PasswordProtected a) where
    toPersistValue = baToPersistValue
    fromPersistValue = baFromPersistValue
instance PersistFieldSql (PasswordProtected a) where
    sqlType _ = baPersistFieldSql
instance HasPEM a => HasPEM (PasswordProtected a) where
    type PEMSafe (PasswordProtected a) = 'True
    pemName a = "PasswordProtected " <> pemProxy a pemName
    pemHeaders a = pemProxy a pemHeaders
instance ToSample (PasswordProtected a) where
    toSamples _ = singleSample $ PasswordProtected $ B.convert b
      where
        b :: String
        b = "\0\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16\17\18\19\20\21\22\23\24"
instance (ByteArrayAccess a, Arbitrary a) => Arbitrary (PasswordProtected a) where
    arbitrary = do
      pwd <- arbitrary
      a <- arbitrary
      throwCryptoError <$> liftCryptoRandom (protect pwd a)
