module Test.Prime.Secret.Client
    ( tests
    ) where

import Prime.Common.Base
import Prime.Secret

import Control.Monad (forM)
import Crypto.Random

import Test.Prime.Common.JSON
import Test.Prime.Common.Persistent
import Test.Prime.Common.NAR (testFromToNar)

data Users = Users Threshold [KeyPair] [KeyPair]
  deriving (Show, Eq)
instance Arbitrary Users where
    arbitrary = do
      participants <- between (1, 8)
      threshold <- if participants == 1 then pure 1 else between (1, participants)
      decodable <- if threshold == participants
                      then pure participants
                      else between (threshold, participants)
      l <- forM [1..participants] $ const arbitrary
      pure $ Users (toInteger threshold) l (take (fromIntegral decodable) l)

data FUsers = FUsers Threshold [KeyPair] [KeyPair]
  deriving (Show, Eq)
instance Arbitrary FUsers where
    arbitrary = do
      participants <- between (1, 8)
      threshold <- if participants == 1 then pure 1 else between (1, participants)
      decodable <- if threshold == 1
                      then pure 0
                      else between (0, threshold - 1)
      l <- forM [1..participants] $ const arbitrary
      pure $ FUsers (toInteger threshold) l (take (fromIntegral decodable) l)

getShareKeypair :: [KeyPair] -> [Share] -> [(KeyPair, Share)]
getShareKeypair [] _  = []
getShareKeypair _  [] = []
getShareKeypair (k:ks) ss =
  let f s = sharePublicKey s == toPublicKey k
   in case find f ss of
      Nothing -> getShareKeypair ks ss
      Just v  -> (k, v) : getShareKeypair ks ss

tests :: Test
tests = Group "Client"
  [ Group "Share"
    [ testFromToJSON (Proxy :: Proxy Share)
    , testFromToPersistent (Proxy :: Proxy Share)
    , testFromToNar (Proxy :: Proxy Share)
    ]
  , Group "Commitment"
    [ testFromToJSON (Proxy :: Proxy Commitment)
    , testFromToPersistent (Proxy :: Proxy Commitment)
    , testFromToNar (Proxy :: Proxy [Commitment])
    ]
  , Property "verifyShare . generateSecret == True" $ \(seed, Users s l _) ->
      let chachadrg = drgNewTest seed
          (_, cs, ss)  = fst $ withDRG chachadrg (generateSecret s (toPublicKey <$> l))
       in and $ verifyShare cs <$> ss
  , Property "recoverSecret == generateSecret" $ \(seed, Users s l p) ->
      let chachadrg = drgNewTest seed
          -- generate the secret
          ((ek, _, ss), seed')  = withDRG chachadrg (generateSecret s (toPublicKey <$> l))

          -- recover all the DecryptedShare
          (dss, _) = withDRG seed' $ forM (getShareKeypair p ss) $ uncurry recoverShare
       in CryptoPassed ek === recoverSecret dss
  , Property "recoverSecret != generateSecret" $ \(seed, FUsers s l p) ->
      let chachadrg = drgNewTest seed
          -- generate the secret
          ((ek, _, ss), seed')  = withDRG chachadrg (generateSecret s (toPublicKey <$> l))

          -- recover all the DecryptedShare
          (dss, _) = withDRG seed' $ forM (getShareKeypair p ss) $ uncurry recoverShare
       in case recoverSecret dss of
            CryptoFailed err -> err === CryptoError_EcScalarOutOfBounds
            CryptoPassed ek' -> propertyCompare "!=" (/=) ek ek'
  ]
