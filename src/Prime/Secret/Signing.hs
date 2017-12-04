-- |
-- Module      : Prime.Secret.Signing
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Prime.Secret.Signing
    ( SigningKey
    , VerifyKey
    , Signature
    , toVerifyKey
    , sign
    , verify
    , signingKeyFromPassword
    ) where

import Prime.Common.Base
import Prime.Common.JSON
import Prime.Common.Persistent
import Prime.Common.Docs

import qualified Prelude
import qualified Crypto.PubKey.Ed25519 as S

import qualified Data.ByteArray as B

import           Crypto.Error
import           Crypto.KDF.PBKDF2 (fastPBKDF2_SHA512, Parameters(..))

import           Prime.Secret.Password (Password, Salt)
import           Prime.Common.PEM

newtype SigningKey = SigningKey S.SecretKey
  deriving (Eq, ByteArrayAccess)
instance HasPEM SigningKey where
    type PEMSafe SigningKey = 'False
    pemName _ = "SigningKey"
    pemHeaders _ = []
instance ToSample SigningKey where
    toSamples _ = singleSample $ throwCryptoError $ signingKeyFromPassword getSample getSample
instance Arbitrary SigningKey where
    arbitrary = throwCryptoError <$>
      (signingKeyFromPassword <$> arbitrary <*> arbitrary)

newtype VerifyKey = VerifyKey S.PublicKey
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON VerifyKey where
    toJSON = toJSON . Base64
instance FromJSON VerifyKey where
    parseJSON a = do
        pk <- unBase64 <$> parseJSON a
        case S.publicKey (pk :: Bytes) of
            CryptoFailed err -> fail (Prelude.show err)
            CryptoPassed vk  -> return $ VerifyKey  vk
instance PersistField VerifyKey where
    toPersistValue = baToPersistValue
    fromPersistValue pv = do
        b <- baFromPersistValue pv
        case S.publicKey (b :: Bytes) of
            CryptoFailed err -> fail (Prelude.show err)
            CryptoPassed a   -> return $ VerifyKey a
instance PersistFieldSql VerifyKey where
    sqlType _ = baPersistFieldSql
instance HasPEM VerifyKey where
    type PEMSafe VerifyKey = 'True
    pemName _ = "VerifyKey"
    pemHeaders _ = []
instance ToSample VerifyKey where
    toSamples _ = singleSample $ toVerifyKey getSample
instance Arbitrary VerifyKey where
    arbitrary = toVerifyKey <$> arbitrary

newtype Signature = Signature S.Signature
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON Signature where
    toJSON = toJSON . Base64
instance FromJSON Signature where
    parseJSON a = do
        pk <- unBase64 <$> parseJSON a
        case S.signature (pk :: Bytes) of
                CryptoFailed err -> fail (Prelude.show err)
                CryptoPassed s   -> return $ Signature s
instance PersistField Signature where
    toPersistValue = PersistByteString . B.convert
    fromPersistValue pv = do
        b <- baFromPersistValue pv
        case S.signature (b :: Bytes) of
            CryptoFailed err -> fail (Prelude.show err)
            CryptoPassed a   -> return $ Signature a
instance PersistFieldSql Signature where
    sqlType _ = baPersistFieldSql
instance HasPEM Signature where
    type PEMSafe Signature = 'True
    pemName _ = "Signature"
    pemHeaders _ = []
instance ToSample Signature where
    toSamples _ = singleSample $ sign getSample getSample
                  ("The quick brown fox jumps over the lazy dog" :: String)
instance Arbitrary Signature where
    arbitrary = do
      sk <- arbitrary
      bytes <- arbitrary :: Gen String
      pure $ sign sk (toVerifyKey sk) bytes

toVerifyKey :: SigningKey -> VerifyKey
toVerifyKey (SigningKey sk) = VerifyKey $ S.toPublic sk

sign :: ByteArrayAccess ba => SigningKey -> VerifyKey -> ba -> Signature
sign (SigningKey sk) (VerifyKey vk) = Signature . S.sign sk vk

verify :: ByteArrayAccess ba => VerifyKey -> ba -> Signature -> Bool
verify (VerifyKey vk) ba (Signature s) = S.verify vk ba s

defaultParameters :: Parameters
defaultParameters = Parameters
    { iterCounts    = 4000
    , outputLength  = 32
    }

signingKeyFromPassword :: Password
                       -> Salt
                       -> CryptoFailable SigningKey
signingKeyFromPassword pwd salt = do
    let pps = fastPBKDF2_SHA512 defaultParameters pwd salt :: B.ScrubbedBytes
    SigningKey <$> S.secretKey pps
