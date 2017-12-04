module Test.Prime.Common (tests) where

import Foundation.Check

import qualified Test.Prime.Common.Time as Time
import qualified Test.Prime.Common.NAR as Nar

tests :: Test
tests = Group "Common"
  [ Time.tests
  , Nar.tests
  ]
