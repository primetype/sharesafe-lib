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

newtype VerifyKey = VerifyKey S.PublicKey
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON VerifyKey where
    toJSON = baToValue
instance FromJSON VerifyKey where
    parseJSON a = do
        pk <- baFromValue a
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

newtype Signature = Signature S.Signature
  deriving (Show, Eq, ByteArrayAccess)
instance ToJSON Signature where
    toJSON = baToValue
instance FromJSON Signature where
    parseJSON a = do
        pk <- baFromValue a
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
