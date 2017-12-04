-- |
-- Module      : Prime.Common.JSON
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Prime.Common.JSON
    ( FromJSON(..)
    , ToJSON(..)
    , object
    , withObject
    , (.:)
    , (.=)
    , binToValue, binFromValue
    , binToBase64, binFromBase64
    , Base16(..), Base64(..), Base64URL(..)
    , baParseJSON
    , encodeJSON
    ) where

import Prime.Common.Base

import Data.Aeson hiding (encode, decode)
import qualified Data.Aeson as JSON
import Data.Aeson.Types (Parser)

import qualified Data.ByteArray.Encoding as B
import Data.ByteString.Char8 (ByteString, pack, unpack)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Binary (encode, decode, Binary)

binToValue :: Binary a => a -> Value
binToValue = toJSON . unpack . binToBase16'

binToBase16' :: Binary a => a -> ByteString
binToBase16' = B.convertToBase B.Base16 . toStrict . encode

binToBase64 :: Binary a => a -> ByteString
binToBase64 = B.convertToBase B.Base64 . toStrict . encode
binFromBase64 :: (ByteArrayAccess ba, Binary a) => ba-> Either LString a
binFromBase64 b = decode . fromStrict <$> B.convertFromBase B.Base64 b

binFromValue :: Binary a => Value -> Parser a
binFromValue v = do
    bs <- pack <$> parseJSON v
    binFromBase16' bs
  where
    binFromBase16' :: Binary a => ByteString -> Parser a
    binFromBase16' bs = case B.convertFromBase B.Base16 bs of
        Left err -> fail err
        Right a  -> return $ decode $ fromStrict a

baParseJSON :: (ByteArrayAccess ba, FromJSON obj) => ba -> Either LString obj
baParseJSON = eitherDecodeStrict . convert

encodeJSON :: ToJSON obj => obj -> ByteString
encodeJSON = toStrict . JSON.encode

newtype Base16 a = Base16 { unBase16 :: a }
  deriving (Show, Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ByteArrayAccess a => ToJSON (Base16 a) where
    toJSON = toJSON . unpack . B.convertToBase B.Base16 . unBase16
instance ByteArray a => FromJSON (Base16 a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (Base16 a): " <> err)
            Right dt -> return $ Base16 dt

newtype Base64 a = Base64 { unBase64 :: a }
  deriving (Show, Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ByteArrayAccess a => ToJSON (Base64 a) where
    toJSON = toJSON . unpack . B.convertToBase B.Base64 . unBase64
instance ByteArray a => FromJSON (Base64 a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base64 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (Base64 a): " <> err)
            Right dt -> return $ Base64 dt

newtype Base64URL a = Base64URL { unBase64URL :: a }
  deriving (Show, Eq, Ord, Typeable, Monoid, ByteArray, ByteArrayAccess)
instance ByteArrayAccess a => ToJSON (Base64URL a) where
    toJSON = toJSON . unpack . B.convertToBase B.Base64URLUnpadded . unBase64URL
instance ByteArray a => FromJSON (Base64URL a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base64URLUnpadded . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (Base64URL a): " <> err)
            Right dt -> return $ Base64URL dt
