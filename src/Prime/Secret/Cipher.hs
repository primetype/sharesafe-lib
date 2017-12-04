{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE Rank2Types #-}

-- |
-- Module      : Prime.Secret.Cipher
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Secret.Cipher
    ( State
    , start
    , mkNonce, Nonce
    , encrypt, encrypt', encryptC, encryptC'
    , decrypt, decrypt', decryptC, decryptC'
    , finalize, Auth
    , Ciphered(..)
    , EncryptionKey
    , encryptionKey
    , generateEncryptionKey
    ) where

import Prime.Common.Base
import Prime.Common.Conduit
import Prime.Common.Docs
import Prime.Common.JSON
import Prime.Common.PEM
import Prime.Common.Persistent

import Foundation.Monad

import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B

import           Crypto.Error
import           Crypto.Random
import           Crypto.MAC.Poly1305 (Auth(..), authTag)
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C

data CipherError
    = CipherError_Cryptonite !CryptoError
    | CipherError_InvalidAuth
    | CipherError_InvalidNonce
  deriving (Show, Eq, Typeable)
instance Exception CipherError

instance MonadFailure CryptoFailable where
    type Failure CryptoFailable = CryptoError
    mFail = CryptoFailed

newtype Ciphered a = Ciphered Bytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance Show (Ciphered a) where
    show = show . f
      where
        f :: Ciphered a -> Bytes
        f = B.convertToBase B.Base64
instance ToJSON (Ciphered a) where
    toJSON = toJSON . Base64
instance FromJSON (Ciphered a) where
    parseJSON a = unBase64 <$> parseJSON a
instance PersistField (Ciphered a) where
    toPersistValue = baToPersistValue
    fromPersistValue = baFromPersistValue
instance PersistFieldSql (Ciphered a) where
    sqlType _ = baPersistFieldSql
instance HasPEM a => HasPEM (Ciphered a) where
    type PEMSafe (Ciphered a) = 'True
    pemName a = "Ciphered " <> pemProxy a pemName
    pemHeaders a = pemProxy a pemHeaders
instance ToSample (Ciphered a) where
    toSamples _ = singleSample $ B.convert ("this is some encryped bytes..." :: String)
instance Arbitrary (Ciphered a) where
    arbitrary = Ciphered . B.convert <$> (arbitrary :: Gen String)

-- | Randomly Generate a Nonce
mkNonce :: MonadRandom randomly => randomly (CryptoFailable Nonce)
mkNonce = C.nonce12 <$> gen
 where
  gen :: MonadRandom randomly => randomly ScrubbedBytes
  gen = getRandomBytes 12

-- | start a cipher state (to encrypt or decrypt only)
start :: ( ByteArrayAccess key
         , ByteArrayAccess header
         )
      => key
      -> Nonce
      -> header
      -> CryptoFailable State
start s nonce header = do
    s1 <- C.initialize s nonce
    return $ C.finalizeAAD $ C.appendAAD header s1

newtype EncryptionKey = EncryptionKey B.ScrubbedBytes
  deriving (Eq, Typeable, ByteArrayAccess)
instance Show EncryptionKey where
    show = show . f
      where
        f :: EncryptionKey -> Bytes
        f = B.convertToBase B.Base64
instance HasPEM EncryptionKey where
    type PEMSafe EncryptionKey = 'False
    pemName _ = "EncryptionKey"
    pemHeaders _ = []
instance Arbitrary EncryptionKey where
    arbitrary = liftCryptoRandom generateEncryptionKey

generateEncryptionKey :: MonadRandom randomly => randomly EncryptionKey
generateEncryptionKey = EncryptionKey <$> getRandomBytes 32

encryptionKey :: B.ScrubbedBytes -> CryptoFailable EncryptionKey
encryptionKey ba
    | B.length ba == 32 = CryptoPassed $ EncryptionKey ba
    | otherwise         = CryptoFailed CryptoError_KeySizeInvalid

encryptC :: (ByteArrayAccess header, ByteArray ba)
         => EncryptionKey
         -> header
         -> Nonce
         -> Conduit ba ba CryptoFailable ()
encryptC enc header nonce = encrypt_ enc header nonce cf'
encryptC' :: (MonadThrow m, ByteArrayAccess header, ByteArray ba)
          => EncryptionKey
          -> header
          -> Nonce
          -> Conduit ba ba m ()
encryptC' enc header nonce = encrypt_ enc header nonce cf

encrypt_ :: (Monad m, ByteArrayAccess header, ByteArray ba)
         => EncryptionKey
         -> header
         -> Nonce
         -> (forall a . CryptoFailable a -> Conduit ba ba m a)
         -> Conduit ba ba m ()
encrypt_ enc header nonce errHandler = do
  st <- errHandler $ start enc nonce header
  yield (B.convert nonce)
  let loop s1 = do
        mbs <- await
        case mbs of
          Nothing -> yield $ B.convert (finalize s1)
          Just bs -> do
            let (b, s2) = encrypt bs s1
            yield b
            loop s2
  loop st

decryptC :: (ByteArrayAccess header, ByteArray ba)
         => EncryptionKey
         -> header
         -> Conduit ba ba CryptoFailable ()
decryptC enc header = decrypt_ enc header cf'
decryptC' :: (MonadThrow m, ByteArrayAccess header, ByteArray ba)
          => EncryptionKey
          -> header
          -> Conduit ba ba m ()
decryptC' enc header = decrypt_ enc header cf
decrypt_ :: (Monad m, ByteArrayAccess header, ByteArray ba)
         => EncryptionKey
         -> header
         -> (forall a . CryptoFailable a -> Conduit ba ba m a)
         -> Conduit ba ba m ()
decrypt_ key header errHandler = do
  nonceBS <- awaitNonce
  nonce <- errHandler $ C.nonce12 (nonceBS :: Bytes)
  st <- errHandler $ start key nonce header

  let loop state1 = do
        ebs <- awaitExcept16 id
        case ebs of
          Left final ->
            case authTag final of
              CryptoPassed final' | C.finalize state1 == final' -> return ()
              _ -> errHandler (CryptoFailed CryptoError_AuthenticationTagSizeInvalid)
          Right bs -> do
            let (bs', state2) = decrypt bs state1
            yield bs'
            loop state2

  loop st
  where
    awaitNonce = do
      mbs <- awaitBytes 12
      case mbs of
        Nothing -> errHandler (CryptoFailed CryptoError_IvSizeInvalid)
        Just bs -> return $ B.convert bs

    awaitExcept16 front = do
      mbs <- await
      case mbs of
        Nothing -> return $ Left $ front B.empty
        Just bs -> do
          let bs' = front bs
          if B.length bs' > 16
            then do
              let (x, y) = B.splitAt (B.length bs' - 16) bs'
              leftover y
              return $ Right x
            else awaitExcept16 (B.append bs')

cf :: MonadThrow m => CryptoFailable a -> m a
cf (CryptoPassed a)   = pure a
cf (CryptoFailed err) = throw (CipherError_Cryptonite err)

cf' :: (MonadFailure m, Failure m ~ CryptoError) => CryptoFailable a -> m a
cf' (CryptoPassed a)   = pure a
cf' (CryptoFailed err) = mFail err *> undefined

-- | encrypt the given stream
--
-- This is a convenient function to cipher small elements
--
-- the result is serialized as follow:
-- `nonce <> ciphered-data <> auth`
--
encrypt' :: (MonadRandom randomly, ByteArray stream, ByteArrayAccess header)
         => EncryptionKey
         -> header
         -> stream -- ^ to encrypt
         -> randomly (CryptoFailable (Ciphered a)) -- ^ encrypted
encrypt' sec header input = do
    fnonce <- mkNonce
    return $ do
        nonce <- fnonce
        l <- runConduit $ yield input .| encryptC sec header nonce .| sinkList
        pure $ B.convert $ mconcat l

-- | decrypt the given stream
decrypt' :: (ByteArray stream, ByteArrayAccess header)
         => EncryptionKey
         -> header
         -> Ciphered a -- ^ to decrypt
         -> CryptoFailable stream -- ^ decrypted
decrypt' sec header input = do
    l <- runConduit $ yield input .| decryptC sec header .| sinkList
    pure $ B.convert $ mconcat l
