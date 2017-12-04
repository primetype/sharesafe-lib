module Test.Prime.Secret.Signing
    ( tests
    ) where

import Prime.Common.Base
import Prime.Secret

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent

tests :: Test
tests = Group "Signing"
  [ Group "VerifyKey"
    [ testFromToJSON (Proxy :: Proxy VerifyKey)
    , testFromToPersistent (Proxy :: Proxy VerifyKey)
    ]
  , Group "Signature"
    [ testFromToJSON (Proxy :: Proxy Signature)
    , testFromToPersistent (Proxy :: Proxy Signature)
    , Property "verify" $ \(pwd, salt, str :: String) ->
        let sk = throwCryptoError $ signingKeyFromPassword pwd salt
            vk = toVerifyKey sk
         in verify vk str (sign sk vk str)
    ]
  ]
