module Test.Prime.Common.JSON
    ( testFromToJSON
    ) where

import Foundation
import Foundation.Check

import Prime.Common.JSON

testFromToJSON :: (ToJSON obj, FromJSON obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
               => proxy obj
               -> Test
testFromToJSON = Property "parseJSON . fromJSON === id" . func
  where
    func :: (ToJSON obj, FromJSON obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
         => proxy obj -> obj -> PropertyCheck
    func _ a = Right a === baParseJSON (encodeJSON a)
