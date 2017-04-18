{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
    , encrypt, encrypt'
    , decrypt, decrypt'
    , finalize, Auth
    , Ciphered(..)
    , EncryptionKey
    , encryptionKey
    , generateEncryptionKey
    ) where

import Prime.Common.Base
import Prime.Common.Persistent
import Prime.Common.JSON

import           Data.ByteArray (view)
import qualified Data.ByteArray as B
import           Control.Monad (when)

import           Crypto.Error
import           Crypto.Random
import           Crypto.MAC.Poly1305 (Auth(..))
import           Crypto.Cipher.ChaChaPoly1305 (Nonce, State, encrypt, decrypt, finalize)
import qualified Crypto.Cipher.ChaChaPoly1305 as C


newtype Ciphered a = Ciphered Bytes
  deriving (Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ToJSON (Ciphered a) where
    toJSON = baToValue
instance FromJSON (Ciphered a) where
    parseJSON = baFromValue
instance PersistField (Ciphered a) where
    toPersistValue = baToPersistValue
    fromPersistValue = baFromPersistValue
instance PersistFieldSql (Ciphered a) where
    sqlType _ = baPersistFieldSql

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

generateEncryptionKey :: MonadRandom randomly => randomly EncryptionKey
generateEncryptionKey = EncryptionKey <$> getRandomBytes 32

encryptionKey :: B.ScrubbedBytes -> CryptoFailable EncryptionKey
encryptionKey ba
    | B.length ba == 32 = CryptoPassed $ EncryptionKey ba
    | otherwise         = CryptoFailed CryptoError_KeySizeInvalid

-- | encrypt the given stream
--
-- This is a convenient function to cipher small elements
--
-- the result is serialized as follow:
-- `auth <> nonce <> ciphered-data`
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
        st <-  start sec nonce header
        let (enc, st') = encrypt input st
        return $ Ciphered $ B.convert (finalize st') <> B.convert nonce <> B.convert enc

-- | decrypt the given stream
decrypt' :: (ByteArray stream, ByteArrayAccess header)
         => EncryptionKey
         -> header
         -> Ciphered a -- ^ to decrypt
         -> CryptoFailable stream -- ^ decrypted
decrypt' sec header (Ciphered auth_nonce_input) = do
    let auth  = Auth $ B.convert $ view auth_nonce_input 0  16
    nonce <- C.nonce12 $ view auth_nonce_input 16 12
    let input = B.drop 28 auth_nonce_input
    st <- start sec nonce header
    let (dec, st') = decrypt input st
    let auth' = finalize st'
    when (auth /= auth') $ CryptoFailed CryptoError_AuthenticationTagSizeInvalid
    return $ B.convert dec
