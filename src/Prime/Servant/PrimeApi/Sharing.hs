-- |
-- Module      : Prime.Servant.PrimeApi.Sharing
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Prime.Servant.PrimeApi.Sharing
    ( UserPublicKey(..)
    , listUserPublicKeys
    , PostPublicKey(..), UserKeyPair(..), Entity(..)
    , postPublicKey
    , retrievePrivateKeys
    , NewShare(..), UserSecretShare(..)
    , postNewShare
    , ShareDetails(..), ShareParticipant(..)
    , getSharesWithMe, getShare
    ) where

import Foundation

import Control.Monad.Except
import Database.Persist.Class
import Database.Persist.Sql
import qualified Database.Esqueleto as E
import Data.Aeson (ToJSON(..), FromJSON(..), object, withObject, (.:), (.=))
import Servant.Server.Experimental.Auth.Cookie

import Prime.Secret

import Prime.Servant.Monad
import Prime.Servant.Models
import Prime.Common.Time

-- Set a PublicKey ------------------------------------------------------------

data PostPublicKey = PostPublicKey
    { ppkComment    :: !(Maybe LString)
    , ppkPublicKey  :: !PublicKey
    , ppkPrivateKey :: !(PasswordProtected PrivateKey)
    }
instance ToJSON PostPublicKey where
    toJSON ppk = object
      [ "comment" .= ppkComment ppk
      , "public_key" .= ppkPublicKey ppk
      , "private_key" .= ppkPrivateKey ppk
      ]
instance FromJSON PostPublicKey where
    parseJSON = withObject "PostPublicKey" $ \o -> PostPublicKey
        <$> o .: "comment"
        <*> o .: "public_key"
        <*> o .: "private_key"

postPublicKey :: WithMetadata Int64 -> PostPublicKey -> App ()
postPublicKey wmid (PostPublicKey comment pk sk) = do
    now <- timeCurrent
    let npk = UserKeyPair (toSqlKey $ wmData wmid) comment now pk sk
    _ <- runDB $ insert npk
    return ()

retrievePrivateKeys :: WithMetadata Int64 -> App [Entity UserKeyPair]
retrievePrivateKeys wmid = runDB $ selectList [UserKeyPairUser ==. (toSqlKey $ wmData wmid)] []

-- Require user's public key --------------------------------------------------

data UserPublicKey = UserPublicKey
    { upkKey     :: !PublicKey
    , upkComment :: !(Maybe LString)
    , upkCreated :: !Time
    , upkUserId  :: !Int64
    }
instance ToJSON UserPublicKey where
    toJSON upk = object
      [ "key" .= upkKey upk
      , "comment" .= upkComment upk
      , "created_time" .= upkCreated upk
      , "user_id" .= upkUserId upk
      ]
instance FromJSON UserPublicKey where
    parseJSON = withObject "UserPublicKey" $ \o -> UserPublicKey
        <$> o .: "key"
        <*> o .: "comment"
        <*> o .: "created_time"
        <*> o .: "user_id"

listUserPublicKeys :: WithMetadata Int64 -> [Char] -> App [UserPublicKey]
listUserPublicKeys _ email = do
    l <- runDB $ E.select $ E.from $ \(ut `E.InnerJoin` ukpt) -> do
              E.on (ut E.^. UserId E.==. ukpt E.^. UserKeyPairUser)
              E.where_ (ut E.^. UserEmail E.==. E.val email)
              E.orderBy [E.asc $ ukpt E.^. UserKeyPairCreated]
              return ( ukpt E.^. UserKeyPairPublic
                     , ukpt E.^. UserKeyPairComment
                     , ukpt E.^. UserKeyPairCreated
                     , ut   E.^. UserId
                     )
    return $ (\(a,b,c,d) -> UserPublicKey (E.unValue a) (E.unValue b) (E.unValue c) (fromSqlKey $ E.unValue d)) <$> l

-- Send Shared Secret ---------------------------------------------------------

data NewShare = NewShare
    { nsComment     :: !(Maybe LString)
    , nsCommitments :: ![Commitment]
    , nsUsers       :: ![UserSecretShare]
    }
instance ToJSON NewShare where
    toJSON upk = object
      [ "comment" .= nsComment upk
      , "commitments" .= nsCommitments upk
      , "users" .= nsUsers upk
      ]
instance FromJSON NewShare where
    parseJSON = withObject "NewShare" $ \o -> NewShare
        <$> o .: "comment"
        <*> o .: "commitments"
        <*> o .: "users"
data UserSecretShare = UserSecretShare
    { ussUserId :: !Int64
    , ussShare  :: !Share
    }
instance ToJSON UserSecretShare where
    toJSON upk = object
      [ "user_id" .= ussUserId upk
      , "share" .= ussShare upk
      ]
instance FromJSON UserSecretShare where
    parseJSON = withObject "UserSecretShare" $ \o -> UserSecretShare
        <$> o .: "user_id"
        <*> o .: "share"

postNewShare :: WithMetadata Int64
             -> NewShare
             -> App ()
postNewShare _ ns = do
    now <- timeCurrent
    runDB $ do
        dbid <- insert $ DBSecret (nsComment ns) (nsCommitments ns) now
        forM_ (nsUsers ns) $ \us -> do
            insert $ DBSecretUser
                dbid
                (toSqlKey $ ussUserId us)
                (ussShare us)

-- Getting a Share -----------------------------------------------------------

data ShareDetails = ShareDetails
    { sdSecretId :: !Int64
    , sdSecret   :: !DBSecret
    , sdUsers    :: ![ShareParticipant]
    }
instance ToJSON ShareDetails where
    toJSON u = object
      [ "secret_id" .= sdSecretId u
      , "secret" .= sdSecret u
      , "users" .= sdUsers u
      ]
instance FromJSON ShareDetails where
    parseJSON = withObject "ShareDetails" $ \o -> ShareDetails
        <$> o .: "secret_id"
        <*> o .: "secret"
        <*> o .: "users"
data ShareParticipant = ShareParticipant
    { spUserId    :: !Int64
    , spUserName  :: !LString
    , spUserEmail :: !LString
    , spUserShare :: !Share
    }
instance ToJSON ShareParticipant where
    toJSON u = object
      [ "user_id" .= spUserId u
      , "user_name" .= spUserName u
      , "user_email" .= spUserEmail u
      , "user_share" .= spUserShare u
      ]
instance FromJSON ShareParticipant where
    parseJSON = withObject "ShareParticipant" $ \o -> ShareParticipant
        <$> o .: "user_id"
        <*> o .: "user_name"
        <*> o .: "user_email"
        <*> o .: "user_share"


getSharesWithMe :: WithMetadata Int64 -> App [ShareDetails]
getSharesWithMe wmid = do
    -- TODO: all of this could be one SQL query

    -- 1. get all secret shared with me
    l <- runDB $ E.select $ E.from $ \(dbsut `E.InnerJoin` dbst) -> do
            E.on (dbsut E.^. DBSecretUserSecret E.==. dbst E.^. DBSecretId)
            E.where_ (dbsut E.^. DBSecretUserUser E.==. E.val mkey)
            return dbst
    -- 2. for every secret, get the details
    runDB $ forM l $ \(Entity sid s) -> do
              r <- E.select $ E.from $ \(dbsut `E.InnerJoin` us) -> do
                              E.on (dbsut E.^. DBSecretUserUser E.==. us E.^. UserId)
                              E.where_ (dbsut E.^. DBSecretUserSecret E.==. E.val sid)
                              return (dbsut, us)
              return $ translate sid s r
  where
    translate :: DBSecretId -> DBSecret -> [(Entity DBSecretUser, Entity User)] -> ShareDetails
    translate sid s l = ShareDetails (fromSqlKey sid) s $ translateUD <$> l

    translateUD (Entity dbsi dbs, Entity uid u) = ShareParticipant
        (fromSqlKey uid)
        (userName u)
        (userEmail u)
        (dBSecretUserShare dbs)
    mkey = toSqlKey $ wmData wmid

getShare :: WithMetadata Int64 -> Int64 -> App ShareDetails
getShare wmid si = runDB $ do
    r <- E.select $ E.from $ \(dbsut `E.InnerJoin` ust `E.InnerJoin` st) -> do
                    E.on (dbsut E.^. DBSecretUserUser E.==. ust E.^. UserId)
                    E.on (dbsut E.^. DBSecretUserSecret E.==. st E.^. DBSecretId)
                    E.where_ (st E.^. DBSecretId E.==. E.val (toSqlKey si))
                    return (st, dbsut, ust)
    case r of
        [] -> error "undefined share"
        (x:xs) -> return $ translate x (x:xs)
  where
    translate :: (Entity DBSecret, Entity DBSecretUser, Entity User)
              -> [(Entity DBSecret, Entity DBSecretUser, Entity User)]
              -> ShareDetails
    translate (Entity sid s, _, _) l = ShareDetails (fromSqlKey sid) s $ translateUD <$> l
    translateUD (_, Entity dbsi dbs, Entity uid u) = ShareParticipant
        (fromSqlKey uid)
        (userName u)
        (userEmail u)
        (dBSecretUserShare dbs)
