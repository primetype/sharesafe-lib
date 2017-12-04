-- |
-- Module      : Prime.Secret.Client
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Prime.Secret.Client
    (
      -- * Secret
      Share(..), ExtraGen, Commitment, EncryptedShare, Threshold
      -- ** generate secret
    , generateSecret
      -- ** verify share
    , verifyShare
      -- ** recove share
    , recoverShare, DecryptedShare
      -- ** recove Secret
    , recoverSecret

    -- * Helpers
    , throwCryptoErrorIO
    , throwCryptoError
    , CryptoFailable(..)
    ) where

import Prime.Common.Base
import Prime.Common.JSON
import Prime.Common.Persistent
import Prime.Common.Conduit
import Prime.Common.NAR

import Foundation.Collection (zip)
import qualified Crypto.PVSS as PVSS
import Crypto.PVSS ( Threshold
                   , escrow
                   , EncryptedShare
                   , DecryptedShare
                   , secretToDhSecret
                   , DhSecret(..)
                   , ExtraGen, Proof
                   , verifyEncryptedShare
                   , shareDecrypt
                   , recover
                   )
import Data.Aeson (ToJSON(..), FromJSON(..), encode, decode', object, (.:), (.=), withObject)
import Crypto.Random (MonadRandom)
import Crypto.Error (CryptoFailable(..), throwCryptoError, throwCryptoErrorIO, CryptoError(..))
import Data.ByteArray (convert)
import Data.ByteString.Lazy (toStrict, fromStrict)

import           Database.Persist.Class (PersistField(..))
import           Database.Persist.Types (PersistValue(..))
import           Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))

import Prime.Secret.Keys
import Prime.Secret.Cipher (EncryptionKey, encryptionKey)

import Control.Exception (catch, SomeException, evaluate)
import System.IO.Unsafe (unsafePerformIO)

-- | User's Share
data Share = Share
    { shareExtraGen   :: ExtraGen
    , shareProof      :: Proof
    , shareEncrypted  :: EncryptedShare
    , sharePublicKey  :: PublicKey
    }
  deriving (Eq, Show, Typeable)
instance ToJSON Share where
    toJSON o = object
      [ "extra_gen"  .= binToValue (shareExtraGen o)
      , "proof"      .= binToValue (shareProof o)
      , "encrypted"  .= binToValue (shareEncrypted o)
      , "publickey"  .= sharePublicKey o
      ]
instance FromJSON Share where
    parseJSON = withObject "Share" $ \o -> Share
        <$> (binFromValue =<< o .: "extra_gen")
        <*> (binFromValue =<< o .: "proof")
        <*> (binFromValue =<< o .: "encrypted")
        <*> o .: "publickey"
instance PersistField Share where
    toPersistValue = PersistByteString . toStrict . encode
    fromPersistValue pv = do
        v <- fromPersistValue pv
        case decode' $ fromStrict v of
            Nothing -> Left "cannot decode persistent value Share"
            Just r  -> Right r
instance PersistFieldSql Share where
    sqlType _ = SqlBlob
instance Arbitrary Share where
    arbitrary = do
      pk <- arbitrary
      (_, _, [s]) <- liftCryptoRandom $ generateSecret 1 [pk]
      pure s
instance IsNarItem Share where
    magicNar = 0x65726168732D5353 -- SS-share
    packNar share = do
      let b1 = convert $ encodeJSON (sharePublicKey share)
      let l1 = length b1
      let b2 = convert $ encodeJSON share
      let l2 = length b2
      -- S S - s h a r e (ShareSafe-share)
      let nh = NarHeader (magicNar @Share) 0 (fromIntegral $ fromCount l1) (fromIntegral $ fromCount l2)
      yield (Header nh)
      yield (Blob $ NarBlob1 b1 azero)
      yield (Blob $ NarBlob2 b2 azero)
    unpackNar _ = do
      Just (Header nh) <- await
      mb1 <- awaitBlob1
      mb2 <- awaitBlob2
      let mv = do
              b1 <- mb1
              b2 <- mb2
              case baParseJSON b1 of
                Left err -> error err
                Right (_ :: PublicKey)  -> case baParseJSON b2 of
                  Left err -> error err
                  Right v  -> pure v
      case mv of
        Nothing -> error "not enought bytes..."
        Just v  -> pure v

-- | Commitment
newtype Commitment = Commitment { unCommitment :: PVSS.Commitment }
    deriving (Eq, Show, Typeable)
instance PVSSCompatible Commitment where
    type PVSSType Commitment = PVSS.Commitment
    toPVSSType = unCommitment
    fromPVSSType = Commitment
instance ToJSON Commitment where
    toJSON = binToValue . toPVSSType
instance FromJSON Commitment where
    parseJSON a = fromPVSSType <$> binFromValue a
instance PersistField Commitment where
    toPersistValue = binToPersistValue . toPVSSType
    fromPersistValue pv = fromPVSSType <$> binFromPersistValue pv
instance PersistFieldSql Commitment where
    sqlType _ = binPersistFieldSql
instance Arbitrary Commitment where
    arbitrary = do
      pk <- arbitrary
      (_, [c], _) <- liftCryptoRandom $ generateSecret 1 [pk]
      pure c
instance IsNarItem [Commitment] where
    magicNar = 0x736D6D6F632D5353 -- SS-comms
    packNar xs = do
      let bs = convert $ encodeJSON xs
      let ln = length bs
      let nh = NarHeader (magicNar @[Commitment]) 0x0001 0 (fromIntegral $ fromCount ln)
      yield (Header nh)
      yield (Blob $ NarBlob1 mempty azero)
      yield (Blob $ NarBlob2 bs     azero)
    unpackNar _ = do
      Just (Header nh) <- await
      _   <- awaitBlob1
      mbs <- awaitBlob2
      case mbs of
        Nothing -> error "not enough bytes"
        Just bs -> case baParseJSON bs of
          Left err -> error err
          Right v  -> pure v

-- | Generate a a Secret (A key to encrypt something) and the list of Shares.o
--
-- The Shares a ordered the same way the public key came in
-- and they contain back the public key associated.
--
-- The Share can be publicly shared, **but the `Secret` must not leak**
--
generateSecret :: MonadRandom randomly
               => Threshold
               -> [PublicKey]
               -> randomly (EncryptionKey, [Commitment], [Share])
generateSecret t l = do
    (eg, sec, p, commitments, shares) <- escrow t (toPVSSType <$> l)
    let DhSecret bs = secretToDhSecret sec
    return ( throwCryptoError $ encryptionKey $ convert bs
           , fromPVSSType <$> commitments
           , (\(a,b) -> (Share eg p b a)) <$> zip l shares
           )

-- | allow anyone to check a given Share is valid for the given commitments
--
-- This will be useful for the Server to verify the received Share to store
-- is valid. And avoid storing/accepting corrupted data.
--
verifyShare :: [Commitment] -> Share -> Bool
verifyShare commitments (Share eg _ es pk) =
  verifyEncryptedShare eg (toPVSSType <$> commitments) (es, toPVSSType pk)

-- | recover the Decrypted Share
--
recoverShare :: MonadRandom randomly
             => KeyPair
             -> Share
             -> randomly DecryptedShare
recoverShare kp (Share _ _ es _) = shareDecrypt (toPVSSType kp) es

-- | recover a secret from the given decrypted share.
--
-- It may or may not fail if the decrypted share are not for the same secret
-- or that there is not enough decrypted share to recover the original secret.
--
recoverSecret :: [DecryptedShare] -> CryptoFailable EncryptionKey
recoverSecret xs = do
    DhSecret dh <- unsafePerformIO (check $ secretToDhSecret $ recover xs)
    encryptionKey (convert dh)
  where
    check :: a -> IO (CryptoFailable a)
    check a = catch (CryptoPassed <$> evaluate a) f
      where
        f :: SomeException -> IO (CryptoFailable a)
        f _ = return (CryptoFailed CryptoError_EcScalarOutOfBounds)
