-- |
-- Module      : Prime.Common.Base
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Common.Base
    ( module X
    ) where

import Foundation as X hiding (error)
import Data.ByteArray as X ( ByteArray
                           , ByteArrayAccess
                           , Bytes
                           , ScrubbedBytes
                           , convert
                           )
