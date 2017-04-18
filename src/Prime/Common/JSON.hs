-- |
-- Module      : Prime.Common.JSON
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Common.JSON
    ( FromJSON(..)
    , ToJSON(..)
    , object
    , withObject
    , (.:)
    , (.=)
    , binToValue, binFromValue
    , baToValue, baFromValue
    ) where

import Prime.Common.Base

import Data.Aeson hiding (encode, decode)
import Data.Aeson.Types (Parser)

import qualified Data.ByteArray.Encoding as B
import Data.ByteString.Char8 (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Binary (encode, decode, Binary)
import qualified Data.Text.Encoding as T

baToValue :: ByteArrayAccess ba => ba -> Value
baToValue = String . T.decodeUtf8 . B.convertToBase B.Base16

baFromValue :: ByteArray ba => Value -> Parser ba
baFromValue v = do
    bs <- T.encodeUtf8 <$> parseJSON v
    either fail return $ B.convertFromBase B.Base16 bs

binToValue :: Binary a => a -> Value
binToValue = String . T.decodeUtf8 . binToBase16'
  where
    binToBase16' :: Binary a => a -> ByteString
    binToBase16' = B.convertToBase B.Base16 . toStrict . encode

binFromValue :: Binary a => Value -> Parser a
binFromValue v = do
    bs <- T.encodeUtf8 <$> parseJSON v
    binFromBase16' bs
  where
    binFromBase16' :: Binary a => ByteString -> Parser a
    binFromBase16' bs = case B.convertFromBase B.Base16 bs of
        Left err -> fail err
        Right a  -> return $ decode $ fromStrict a
