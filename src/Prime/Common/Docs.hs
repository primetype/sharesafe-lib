-- |
-- Module      : Prime.Common.Docs
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
--

module Prime.Common.Docs
    ( getSample
    , module X
    ) where

import Prime.Common.Base
import Servant.Docs as X

getSample :: ToSample a => a
getSample = f Proxy
  where
    f :: ToSample a => Proxy a -> a
    f p = let ((_,a):_) = toSamples p in a
