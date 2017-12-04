module Test.Prime.Secret.Password
    ( tests
    , testFromToPasswordProtected
    ) where

import Prime.Common.Base
import Prime.Secret

import Crypto.Random

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent

testFromToPasswordProtected :: (ByteArray obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
                            => proxy obj
                            -> Test
testFromToPasswordProtected = Property "recover pwd . protect pwd === id" . func
  where
    func :: (ByteArray obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
         => proxy obj -> ((Word64, Word64, Word64, Word64, Word64), Password, obj) -> PropertyCheck
    func _ (seed, pwd, a) = a === a'
      where
        a' = throwCryptoError $ do
              p <- fst $ withDRG (drgNewTest seed) $ protect pwd a
              recover pwd p

tests :: Test
tests = Group "Password"
  [ Group "Password"
    [ testFromToJSON (Proxy :: Proxy Password)
    ]
  , Group "Salt"
    [ testFromToJSON (Proxy :: Proxy Salt)
    ]
  , Group "PasswordProtected"
    [ Group "PasswordProtected Salt"
      [ testFromToJSON (Proxy :: Proxy (PasswordProtected Salt))
      , testFromToPersistent (Proxy :: Proxy (PasswordProtected Salt))
      , testFromToPasswordProtected (Proxy :: Proxy Salt)
      ]
    , Group "PasswordProtected PrivateKey"
      [ testFromToJSON (Proxy :: Proxy (PasswordProtected PrivateKey))
      , testFromToPersistent (Proxy :: Proxy (PasswordProtected PrivateKey))
      , testFromToPasswordProtected (Proxy :: Proxy PrivateKey)
      ]
    ]
  ]
