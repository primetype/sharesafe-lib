module Prime.App.Env
    ( getUserKeyPair
    , openKeyPair
    , password
    , newPassword
    , writeKeyPair
    , withPublicKey
    ) where

import Prelude (error)
import Control.Monad (unless)
import Prime.App.Monad
import Prime.Common.Base
import Prime.Common.PEM
import Prime.Secret
import           System.Directory (doesFileExist)
import           System.Console.Haskeline (InputT)
import qualified System.Console.Haskeline as H
import           Data.ByteString.Char8 (pack)

openKeyPair :: LString -> App KeyPair
openKeyPair fp = do
    b <- liftIO $ doesFileExist fp
    if b
        then do
            p <- password
            withKeyPair p fp return
        else mFail "No KeyPair"

getUserKeyPair :: App KeyPair
getUserKeyPair = do
    mkp <- get userKeyPair
    case mkp of
        Nothing -> mFail "Cannot find the user KeyPair."
        Just kp -> return kp

withKeyPair :: Password -> LString -> (KeyPair -> App a) -> App a
withKeyPair pwd fp f = do
  e <- liftIO $ pemRead fp $ \l -> (,)
          <$> findPem l (Proxy :: Proxy PublicKey)
          <*> findPem l (Proxy :: Proxy (PasswordProtected PrivateKey))
  case e of
      Left err -> mFail $ "keypair error: " <> err
      Right Nothing -> mFail $ "Cannot find PEM file `" <> fp <> "'"
      Right (Just (pemPk, pemPppk)) -> do
        let pk    = convert $ pemContent pemPk
        let pppks = convert $ pemContent pemPppk
        let sk = throwCryptoError $ recover pwd pppks
        f $ KeyPair sk pk

withPublicKey :: LString -> (PublicKey -> App a) -> App a
withPublicKey fp f = do
    e <- liftIO $ pemRead fp $ flip findPem (Proxy :: Proxy PublicKey)
    case e of
        Left err -> mFail err
        Right Nothing -> mFail $ "Cannot find PEM file `" <> fp <> "'"
        Right (Just pemPk) -> f $ convert $ pemContent pemPk


writeKeyPair :: KeyPair -> LString -> App ()
writeKeyPair kp fp = do
    -- TODO: check the file is not already being used
    pwd <- password
    pks <- throwCryptoError <$> protect pwd (toPrivateKey kp)
    liftIO $ do
        pemSave fp pks
        pemSave fp (toPublicKey kp)


-- | get password or ask for it
password :: App Password
password = do
    mp <- get userPassword
    case mp of
        Nothing -> askPassword
        Just p  -> return p
  where
    askPassword :: App Password
    askPassword = do
        p <- runHL go
        withState $ \s -> ((), s { userPassword = Just p })
        return p
      where
        go :: InputT IO Password
        go = do
            mp <- H.getPassword (Just '#') "enter your password: "
            case mp of
              Nothing -> go -- TODO add a message...
              Just p  -> return $ convert . pack $ p

-- | set a new password
newPassword :: App Password
newPassword = do
    p <- runHL go
    withState $ \s -> ((), s { userPassword = Just p })
    return p
  where
    go :: InputT IO Password
    go = do
      mp1 <- H.getPassword (Just '#') "enter new password: "
      mp2 <- H.getPassword (Just '#') "enter your password again: "
      unless (mp1 == mp2) $ error "invalid password..."
      case mp1 of
          Nothing -> error "no password entered..."
          Just p  -> return $ convert . pack $ p
