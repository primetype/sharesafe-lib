-- |
-- Module      : Prime.Servant.PrimeApi
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleInstances #-}

module Prime.Servant.PrimeApi
    ( PrimeAPI
    , primeApi
    , primeServer
    ) where

import Foundation

import Servant

import Prime.Servant.Monad
import Prime.Servant.Models

import Prime.Servant.PrimeApi.Enroll
import Prime.Servant.PrimeApi.Login
import Prime.Servant.PrimeApi.Sharing

import Servant.Server.Experimental.Auth.Cookie

type PrimeAPI = "user" :> "enroll" :> ReqBody '[JSON] EnrollRequest :> Post '[JSON] EnrollResponse
  -- user identification
           :<|> "user" :> "login" :> Capture "user_email" LString :> Get '[JSON] UserIdentification
           :<|> "user" :> "login" :> Capture "user" Int64 :> ReqBody '[JSON] UserIdentificationChallenge :> Post '[JSON] (Cookied ())
  -- user's personal keys
           :<|> "user" :> AuthProtect "cookie-auth" :> ReqBody '[JSON] PostPublicKey :> Post '[JSON] ()
           :<|> "user" :> AuthProtect "cookie-auth" :> Get '[JSON] [Entity UserKeyPair]
  -- get one user public keys
           :<|> "user" :> AuthProtect "cookie-auth" :> Capture "user_email" LString :> Get '[JSON] [UserPublicKey]
  -- secret sharing
           :<|> "pvss" :> AuthProtect "cookie-auth" :> ReqBody '[JSON] NewShare :> Post '[JSON] ()
           :<|> "pvss" :> AuthProtect "cookie-auth" :> "list" :> Get '[JSON] [ShareDetails]
           :<|> "pvss" :> AuthProtect "cookie-auth" :> Capture "share_id" Int64 :> Get '[JSON] ShareDetails
  -- user retrival of password
  -- TODO would be nice to do that in one query
--           :<|> "user" :> "password" :> Get '[JSON] (Entity UserPassword)
--           :<|> "user" :> "password" :> Capture "id" Int64 :> Get '[JSON] [UserPasswordShares]
  -- lookup user

primeApi :: Proxy PrimeAPI
primeApi = Proxy

primeServer :: ServerT PrimeAPI App
primeServer = enrollUser :<|> loginUserStep1 :<|> loginUserStep2
         :<|> postPublicKey :<|> retrievePrivateKeys
         :<|> listUserPublicKeys
         :<|> postNewShare :<|> getSharesWithMe :<|> getShare
