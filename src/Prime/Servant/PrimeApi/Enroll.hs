-- |
-- Module      : Prime.Servant.PrimeApi.Enroll
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Prime.Servant.PrimeApi.Enroll
    ( EnrollRequest(..)
    , EnrollResponse(..)
    , UserIdentificationData(..)
    , UserIdentificationChallenge(..)
    , enrollUser
    , checkUserIdentificationChallenge
    ) where

import Foundation

import Database.Persist.Class
import Database.Persist.Sql
import Data.Aeson (ToJSON(..), FromJSON(..), object, withObject, (.:), (.=))
import Data.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Data.ByteArray.Encoding as B
import           Data.ByteString.Char8 (pack, unpack)

import Prime.Secret

import Prime.Servant.Monad
import Prime.Servant.Models
import Prime.Common.Time

data EnrollRequest  = EnrollRequest
        { erUserName       :: !LString
        , erUserEmail      :: !LString
        , erIdentification :: !UserIdentificationData
        , erChallenge      :: !UserIdentificationChallenge
        } deriving (Eq, Typeable)
instance ToJSON EnrollRequest where
    toJSON er = object
        [ "name"           .= erUserName er
        , "email"          .= erUserEmail er
        , "identification" .= erIdentification er
        , "challenge"      .= erChallenge er
        ]
instance FromJSON EnrollRequest where
    parseJSON = withObject "EnrollRequest" $ \o ->
      EnrollRequest
        <$> o .: "name"
        <*> o .: "email"
        <*> o .: "identification"
        <*> o .: "challenge"

newtype EnrollResponse = EnrollResponse (Entity User)
  deriving (Show, ToJSON, FromJSON)

enrollUser :: EnrollRequest -> App EnrollResponse
enrollUser er = do
    -- check the identification details are consistent
    checkUserIdentificationChallenge
        (uidVerifyKey $ erIdentification er)
        (erChallenge er)

    now <- timeCurrent

    eu <- runDB $ do
              let user = User (erUserEmail er) (erUserName er) now
              u <- insert user
              _ <- insert $ UserIdentification
                                u
                                (uidVerifyKey $ erIdentification er)
                                (uidSalt      $ erIdentification er)
              return $ Entity u user
    return $ EnrollResponse eu

data UserIdentificationData = UserIdentificationData
    { uidVerifyKey :: !VerifyKey
    , uidSalt      :: !(PasswordProtected Salt)
    } deriving (Eq)
instance ToJSON UserIdentificationData where
    toJSON uid = object
        [ "verify_key" .= uidVerifyKey uid
        , "salt"       .= uidSalt uid
        ]
instance FromJSON UserIdentificationData where
    parseJSON = withObject "UserIdentificationData" $ \o ->
      UserIdentificationData
        <$> o .: "verify_key"
        <*> o .: "salt"

data UserIdentificationChallenge = UserIdentificationChallenge
    { uicSignedData :: !Bytes
    , uicSignature  :: !Signature
    } deriving (Eq, Show)
instance ToJSON UserIdentificationChallenge where
    toJSON uic = object
        [ "data"      .= (Base16 $ uicSignedData uic)
        , "signature" .= uicSignature uic
        ]
instance FromJSON UserIdentificationChallenge where
    parseJSON = withObject "UserIdentificationChallenge" $ \o ->
      UserIdentificationChallenge
        <$> (unBase16 <$> o .: "data")
        <*> o .: "signature"

newtype Base16 a = Base16 { unBase16 :: a }
  deriving (Eq, Ord, Show)
instance ByteArrayAccess a => ToJSON (Base16 a) where
    toJSON (Base16 a) = toJSON $ unpack $ B.convertToBase B.Base16 a
instance ByteArray a => FromJSON (Base16 a) where
    parseJSON a = do
        r <- B.convertFromBase B.Base16 . pack <$> parseJSON a
        case r of
            Left err -> fail ("Failed To Parse (Base16 a): " <> err)
            Right pk -> return $ Base16 pk

checkUserIdentificationChallenge :: VerifyKey -> UserIdentificationChallenge -> App ()
checkUserIdentificationChallenge vk uic
    | verify vk (uicSignedData uic) (uicSignature uic) = return ()
    | otherwise = error "identification check failed. BadPassword"
