module Test.Prime.Common.Time
    ( tests
    ) where

import Foundation
import Foundation.Check

import Prime.Common.Time

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent

proxy :: Proxy Time
proxy = Proxy

tests :: Test
tests = Group "Time"
  [ testFromToJSON proxy
  , testFromToPersistent proxy
  ]
