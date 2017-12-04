module Test.Prime.Secret (tests) where

import Foundation.Check

import qualified Test.Prime.Secret.Keys as Keys
import qualified Test.Prime.Secret.Password as Password
import qualified Test.Prime.Secret.Signing as Signing
import qualified Test.Prime.Secret.Cipher as Cipher
import qualified Test.Prime.Secret.Client as Client

tests :: Test
tests = Group "Secret"
  [ Keys.tests
  , Password.tests
  , Signing.tests
  , Cipher.tests
  , Client.tests
  ]
