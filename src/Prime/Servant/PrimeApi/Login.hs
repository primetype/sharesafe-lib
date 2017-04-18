-- |
-- Module      : Prime.Servant.PrimeApi.Login
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Prime.Servant.PrimeApi.Login
    (
      loginUserStep1
    , loginUserStep2
    ) where

import Foundation

import Control.Monad.Except
import Database.Persist.Class
import Database.Persist.Sql
import Control.Monad.Reader
import Servant
import qualified Database.Esqueleto as E

import Servant.Server.Experimental.Auth.Cookie

import Prime.Servant.Monad
import Prime.Servant.Models

import Prime.Servant.PrimeApi.Enroll
    ( UserIdentificationChallenge(..)
    , checkUserIdentificationChallenge
    )

loginUserStep1 :: LString -> App UserIdentification
loginUserStep1 email = do
    r <- runDB $ E.select $ E.from $ \(user `E.InnerJoin` uid) -> do
                    E.on (user E.^. UserId E.==. uid E.^. UserIdentificationUser)
                    E.where_ (user E.^. UserEmail E.==. E.val email)
                    return uid
    case r of
        [x] -> return $ entityVal x
        _   -> throwError err404

loginUserStep2 :: Int64 -> UserIdentificationChallenge -> App (Cookied ())
loginUserStep2 uid uic = do
    mui <- runDB $ getBy (UniqueUserIdentification $ toSqlKey uid)
    ui <- maybe (throwError err404) return mui
    let vk = userIdentificationVerifyKey $ entityVal ui

    checkUserIdentificationChallenge vk uic

    -- add session
    acs <- asks getAuthCookieSettings
    rs <- asks getRandomSource
    sks <- asks getKeySetServer

    addSession acs rs sks uid ()
