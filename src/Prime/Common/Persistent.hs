-- |
-- Module      : Prime.Common.Persistent
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Common.Persistent
    ( PersistField(..)
    , PersistValue(..)
    , PersistFieldSql(..)
    , SqlType(..)
    , binToPersistValue
    , binFromPersistValue
    , binPersistFieldSql
    , baToPersistValue
    , baFromPersistValue
    , baPersistFieldSql
    ) where

import Prime.Common.Base

import Database.Persist.Class (PersistField(..))
import Database.Persist.Types (PersistValue(..))
import Database.Persist.Sql   (PersistFieldSql(..), SqlType(..))

import qualified Data.ByteArray as B (convert)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Binary (encode, decode, Binary)
import Data.Text (Text)

binToPersistValue :: Binary a => a -> PersistValue
binToPersistValue = PersistByteString . toStrict . encode

binFromPersistValue :: Binary a => PersistValue -> Either Text a
binFromPersistValue v = decode . fromStrict <$> fromPersistValue v

baToPersistValue :: ByteArrayAccess ba => ba -> PersistValue
baToPersistValue = PersistByteString . B.convert
baFromPersistValue :: ByteArray ba => PersistValue -> Either Text ba
baFromPersistValue v = f <$> fromPersistValue v
  where
    f :: ByteArray ba => ByteString -> ba
    f = B.convert

binPersistFieldSql :: SqlType
binPersistFieldSql = SqlBlob

baPersistFieldSql :: SqlType
baPersistFieldSql = SqlBlob
