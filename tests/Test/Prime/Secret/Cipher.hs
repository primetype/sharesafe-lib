module Test.Prime.Secret.Cipher
    ( tests
    ) where

import Prime.Common.Base
import Prime.Secret

import qualified Data.ByteArray as B
import Crypto.Random

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent

tests :: Test
tests = Group "Cipher"
  [ Group "Ciphered"
    [ testFromToJSON (Proxy :: Proxy (Ciphered String))
    , testFromToPersistent (Proxy :: Proxy (Ciphered String))
    ]
  , Group "encrypt"
    [ Property "decrypt' . encrypt' == id" testEncryption
    ]
  ]
  where
    testEncryption (seed, ek, str :: [Word8]) =
        let r  = throwCryptoError $ fst $ withDRG chachadrg (encrypt' ek header b)
            b' = throwCryptoError $ decrypt' ek header r
         in b === b'
      where
        b :: Bytes
        b = B.pack str
        header :: Bytes
        header = mempty
        chachadrg = drgNewTest seed
