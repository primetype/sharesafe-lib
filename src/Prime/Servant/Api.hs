-- |
-- Module      : Prime.Servant.Api
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators              #-}

module Prime.Servant.Api (app) where

import Foundation

import qualified Prelude
import Control.Monad.Except
import Control.Monad.Reader        (runReaderT)
import Control.Monad.Catch (catch)
import Network.Wai                 (Application)
import Servant
import qualified Data.ByteString.Char8 as BSC8
import qualified Data.ByteString.Lazy as BL
import Network.Wai
import Network.HTTP.Types

import Servant.Server.Experimental.Auth
import Servant.Server.Experimental.Auth.Cookie
import Prime.Servant.Monad
import Prime.Servant.PrimeApi

appToServer :: Config -> Server PrimeAPI
appToServer cfg = enter (convertApp cfg) primeServer

convertApp :: Config -> App :~> ExceptT ServantErr IO
convertApp cfg = Nat (flip runReaderT cfg . runApp)

type DocumentedAPI = PrimeAPI

documentedAPI :: Proxy DocumentedAPI
documentedAPI = Proxy

serveDocumented :: Config -> Server DocumentedAPI
serveDocumented = appToServer

type AppAPI = DocumentedAPI :<|> "doc" :> Raw

appApi :: Proxy AppAPI
appApi = Proxy

app :: Config -> Application
app cfg = serveWithContext
    appApi
    ((authHandler cfg) :. EmptyContext)
    (server cfg)

authHandler :: Config -> AuthHandler Request (WithMetadata Int64)
authHandler cfg = mkAuthHandler $ \request -> do
    r <- (getSession (getAuthCookieSettings cfg) (getKeySetServer cfg) request) `catch` handleEx
    case r of
        Nothing -> throwError err403 {errBody = "No cookies"}
        Just i  -> return i
  where
    handleEx :: AuthCookieException -> Handler (Maybe (WithMetadata Int64))
    handleEx ex = throwError err403 {errBody = BL.fromStrict . BSC8.pack $ Prelude.show ex}

server :: Config -> Server AppAPI
server cfg = serveDocumented cfg :<|> serveDocs
  where
    plain = ("Content-Type", "text/plain")
    serveDocs :: Request -> (Network.Wai.Response -> IO ResponseReceived)
              -> IO ResponseReceived
    serveDocs _ respond = respond $ responseLBS ok200 [plain] "not yet generated"
{-
          respond $ responseLBS ok200 [plain] docsBS
    docsBS :: ByteString
    docsBS = encodeUtf8 . pack . markdown
           $ docsWithIntros [intro] documentedAPI
      where intro = DocIntro "Welcome" ["This is our super webservice's API.", "Enjoy!"]
-}
