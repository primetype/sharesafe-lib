module Test.Prime.Secret.Keys
    ( tests
    ) where

import Foundation
import Foundation.Check

import Prime.Secret

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent

tests :: Test
tests = Group "Keys"
  [ Group "PublicKey"
    [ testFromToJSON (Proxy :: Proxy PublicKey)
    , testFromToPersistent (Proxy :: Proxy PublicKey)
    ]
  ]
