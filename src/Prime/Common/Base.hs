-- |
-- Module      : Prime.Common.Base
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Common.Base
    ( module X
    , liftCryptoRandom
    ) where

import Control.Monad as X (when, unless)
import Prelude as X (Show(..), error, lookup)
import Foundation as X hiding (Show, show, error)
import Foundation.Check as X
import Foundation.Collection as X (nonEmpty_)

import Data.ByteArray as X ( ByteArray
                           , ByteArrayAccess
                           , Bytes
                           , ScrubbedBytes
                           , convert
                           )

import Crypto.Random

-- | function to lift Cryptonite's random crypto into the Foundation's Check's
-- Arbitrary
liftCryptoRandom :: MonadPseudoRandom ChaChaDRG a -> Gen a
liftCryptoRandom action = do
    chachadrg <- drgNewTest <$> arbitrary
    pure $ fst $ withDRG chachadrg action
