-- |
-- Module      : Prime.Servant.Client
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
module Prime.Servant.Client
    ( -- * Enroll
      enroll
    , -- * Login
      loginStep1
    , loginStep2


    , -- *
      sendShare
    , getShare, getSharesWithMe

    , -- * lookup user details
      sendPublicKey, getPrivateKeys
    , lookupUser

    , module X
    ) where


import Prime.Secret as X
import Prime.Servant.PrimeApi
import Prime.Servant.PrimeApi.Enroll as X
  (EnrollRequest(..), UserIdentificationData(..), UserIdentificationChallenge(..)
  ,EnrollResponse(..)
  )
import Prime.Servant.Models as X
  ( User(..)
  , UserKeyPair(..)
  , DBSecret(..), DBSecretUser(..)
  )
import Prime.Servant.PrimeApi.Sharing as X
  ( NewShare(..)
  , UserSecretShare(..), UserKeyPair(..), Entity(..)
  , ShareDetails(..), ShareParticipant(..)
  , UserPublicKey(..), PostPublicKey(..)
  )
import Servant.API
import Servant.Client


enroll :<|> loginStep1 :<|> loginStep2
       :<|> sendPublicKey :<|> getPrivateKeys :<|> lookupUser
       :<|> sendShare
       :<|> getSharesWithMe :<|> getShare
       = client primeApi
