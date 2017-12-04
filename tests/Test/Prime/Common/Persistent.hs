module Test.Prime.Common.Persistent
    ( testFromToPersistent
    ) where

import Foundation
import Foundation.Check

import Prime.Common.Persistent

testFromToPersistent :: (PersistField obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
                     => proxy obj
                     -> Test
testFromToPersistent = Property "fromPersistValue . toPersistValue === id" . func
  where
    func :: (PersistField obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
         => proxy obj -> obj -> PropertyCheck
    func _ a = Right a === fromPersistValue (toPersistValue a)
