-- |
-- Module      : Prime.Secret.Keys
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}

module Prime.Secret.Keys
    ( PVSSCompatible(..)
    , KeyPair(..)
    , PublicKey(..)
    , PrivateKey
    , keyPairGenerate
    ) where

import Prime.Common.Base
import Prime.Common.Docs
import Prime.Common.JSON
import Prime.Common.Persistent
import Prime.Common.PEM

import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import qualified Crypto.PVSS as PVSS
import           Crypto.Random (MonadRandom)

import Data.ByteString.Char8 (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Binary (encode, decode, Binary)

class PVSSCompatible a where
    type PVSSType a
    toPVSSType :: a -> PVSSType a
    fromPVSSType :: PVSSType a -> a

-- | convert one of these binary stuff into a memory compatible element
--
-- so it is compatible with ByteArray/ByteArrayAccess operators
--
toBS :: (PVSSCompatible a, Binary (PVSSType a)) => a -> ByteString
toBS = toStrict . encode . toPVSSType

-- | convert one of these binary stuff into a Strict.bytestring
--
-- so it is compatible with ByteArrayAccess operators
--
fromBS :: (PVSSCompatible a, Binary (PVSSType a)) => ByteString -> a
fromBS = fromPVSSType . decode . fromStrict

-- | Generate a Public Key and a Secret for, store them in the key pair
keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = fromPVSSType <$> PVSS.keyPairGenerate

-- | Public Key, can be safely Shared.
--
-- PublicKey are used to generate new secrets and identify a user
--
newtype PublicKey = PublicKey { unPublicKey :: PVSS.PublicKey }
  deriving (Eq)
instance Show PublicKey where
    show = show . (B.convertToBase B.Base64 :: PublicKey -> Bytes)
instance Ord PublicKey where
    compare a b = compare (toBS a) (toBS b)
instance Monoid PublicKey where
    mempty  = undefined
    mappend = undefined
instance PVSSCompatible PublicKey where
    type PVSSType PublicKey = PVSS.PublicKey
    toPVSSType = unPublicKey
    fromPVSSType = PublicKey
instance ByteArray PublicKey where
    allocRet n f = second fromBS <$> B.allocRet n f
instance ByteArrayAccess PublicKey where
    length = B.length . toBS
    withByteArray pk = B.withByteArray (toBS pk)
instance ToJSON PublicKey where
    toJSON = toJSON . Base64
instance FromJSON PublicKey where
    parseJSON a = unBase64 <$> parseJSON a
instance PersistField PublicKey where
    toPersistValue = binToPersistValue . unPublicKey
    fromPersistValue a = PublicKey <$> binFromPersistValue a
instance PersistFieldSql PublicKey where
    sqlType _ = binPersistFieldSql
instance HasPEM PublicKey where
    type PEMSafe PublicKey = 'True
    pemName _ = "PublicKey"
    pemHeaders _ = []
instance ToSample PublicKey where
    toSamples _ = singleSample
                $ either undefined id
                $ B.convertFromBase B.Base64
                  ("A3twGygrTf6/TRHNzWVEG78ltGLuY69gnTBMTDY+i6Yh" :: String)
instance Arbitrary PublicKey where
    arbitrary = toPublicKey <$> arbitrary

-- | PrivateKey, to not share as is.
newtype PrivateKey = PrivateKey { unPrivateKey :: PVSS.PrivateKey }
  deriving (Eq)
instance Show PrivateKey where
    show = show . (B.convertToBase B.Base64 :: PrivateKey -> Bytes)
instance Ord PrivateKey where
    compare a b = compare (toBS a) (toBS b)
instance Monoid PrivateKey where
    mempty  = undefined
    mappend = undefined
instance PVSSCompatible PrivateKey where
    type PVSSType PrivateKey = PVSS.PrivateKey
    toPVSSType = unPrivateKey
    fromPVSSType = PrivateKey
instance ByteArrayAccess PrivateKey where
    length = B.length . toBS
    withByteArray pk = B.withByteArray (toBS pk)
instance ByteArray PrivateKey where
    allocRet n f = second fromBS <$> B.allocRet n f
instance HasPEM PrivateKey where
    type PEMSafe PrivateKey = 'False
    pemName _ = "SecretKey"
    pemHeaders _ = []
instance ToSample PrivateKey where
    toSamples _ = singleSample
                $ either undefined id
                $ B.convertFromBase B.Base64
                  ("c2t+ZqM5cnLp0VU8cpEtOlzE2r0m642vnZ5fNxYjXGE=" :: String)
instance Arbitrary PrivateKey where
    arbitrary = toPrivateKey <$> arbitrary

-- | Key Pair
data KeyPair = KeyPair
    { toPrivateKey :: !PrivateKey
    , toPublicKey  :: !PublicKey
    } deriving (Show, Eq)
instance PVSSCompatible KeyPair where
    type PVSSType KeyPair = PVSS.KeyPair
    toPVSSType kp = PVSS.KeyPair (toPVSSType $ toPrivateKey kp)
                                 (toPVSSType $ toPublicKey kp)
    fromPVSSType kp = KeyPair (fromPVSSType $ PVSS.toPrivateKey kp)
                              (fromPVSSType $ PVSS.toPublicKey kp)
instance ToSample KeyPair where
    toSamples _ = singleSample KeyPair
        { toPrivateKey = getSample
        , toPublicKey  = getSample
        }
instance Arbitrary KeyPair where
    arbitrary = liftCryptoRandom keyPairGenerate
