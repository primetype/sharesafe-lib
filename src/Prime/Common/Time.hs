-- |
-- Module      : Prime.Common.Time
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NoOverloadedStrings #-}

module Prime.Common.Time
    ( Time
    , Elapsed
    , timeCurrent
    , timeAdd
    , H.timePrint
    , getTimeInSec, timeFromSec
    ) where

import qualified Prelude
import Prime.Common.Base
import Prime.Common.JSON
import Prime.Common.Persistent

import           Foundation.Numerical (Subtractive(..))
import           Data.Hourglass (Elapsed, Timeable)
import qualified Data.Hourglass as H
import qualified Time.System as H
import           Control.Monad.IO.Class

import           Servant.Docs

newtype Time = Time Elapsed
  deriving (Eq, Ord, Typeable, H.Time, Timeable)
instance Prelude.Show Time where
    show = H.timePrint H.ISO8601_DateAndTime
instance ToJSON Time where
    toJSON = toJSON . H.timePrint "EPOCH"
instance FromJSON Time where
    parseJSON o = do
        a <- parseJSON o
        case H.timeParse "EPOCH" a of
            Nothing -> fail "unable to parse EPOCH time"
            Just t  -> return $ Time $ H.timeGetElapsed t
instance PersistField Time where
    toPersistValue = PersistInt64 . getTimeInSec
    fromPersistValue a = timeFromSec <$> fromPersistValue a
instance PersistFieldSql Time where
    sqlType _ = SqlInt64
instance Subtractive Time where
    type Difference Time = Elapsed
    (-) (Time a1) (Time a2) = a1 Prelude.- a2
instance ToSample Time where
    toSamples _ = singleSample $ Time 1505410855
instance Arbitrary Time where
    arbitrary = timeFromSec . fromIntegral <$> between (1, 1510690250)

getTimeInSec :: Time -> Int64
getTimeInSec (Time (H.Elapsed (H.Seconds i))) = i

timeFromSec :: Int64 -> Time
timeFromSec = Time . H.Elapsed . H.Seconds

timeCurrent :: MonadIO io => io Time
timeCurrent = Time <$> liftIO H.timeCurrent

timeAdd :: Time -> Elapsed -> Time
timeAdd (Time t) e = Time $ t Prelude.+ e
