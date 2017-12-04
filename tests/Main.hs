module Main (main) where

import Foundation
import Foundation.Check
import Foundation.Check.Main

import qualified Test.Prime.Common as Common
import qualified Test.Prime.Secret as Secret

main :: IO ()
main = defaultMain $ Group "Prime"
  [ Common.tests
  , Secret.tests
  ]
