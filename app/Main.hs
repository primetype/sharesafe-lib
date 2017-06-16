{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Main (main) where

import Prelude (error)
import Control.Monad (forM, unless, forM_)
import Options.Applicative
import System.FilePath
import System.IO.Unsafe (unsafePerformIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Aeson (encode, eitherDecode)
import Codec.Compression.GZip (compress, decompress)

import Prime.Common.Base
import Prime.Common.JSON
import Prime.Secret

import Prime.App.Monad
import Prime.App.Env

newtype GenerateKeyPairOptions = GenerateKeyPairOptions
    { gkpoOutput :: FilePath
    }
  deriving (Show)

data NewSecretOptions = NewSecretOptions
    { myPrivateKey :: !FilePath
    , othersPublicKey :: ![FilePath]
    , toEncryptFiles :: ![FilePath]
    , outputTo :: !FilePath
    }
  deriving (Show)

data ReadSecretOptions = ReadSecretOptions
    { rsoMyPrivateKey :: !FilePath
    , rsoSecret       :: !FilePath
    }
  deriving (Show)

data Command
    = GenerateKeyPair GenerateKeyPairOptions
    | NewSecret NewSecretOptions
    | ReadSecret ReadSecretOptions
  deriving (Show)

generateKeyPairOptions :: Parser GenerateKeyPairOptions
generateKeyPairOptions = GenerateKeyPairOptions
    <$> argument str (metavar "OUTPUT" <> value (unsafePerformIO defaultKeyPairPath))

newSecretOptions :: Parser NewSecretOptions
newSecretOptions = NewSecretOptions
    <$> strOption (long "keypair" <> metavar "MY_KEYPAIR" <> value (unsafePerformIO defaultKeyPairPath))
    <*> some (strOption (long "recipient" <> long "to" <> metavar "RECIPIENT_PUBLICKEY"))
    <*> some (strOption (long "input" <> short 'i' <> metavar "INPUT_TO_ENCRYPT"))
    <*> strOption (long "output" <> short 'o' <> metavar "OUTPUT")

readSecretOptions :: Parser ReadSecretOptions
readSecretOptions = ReadSecretOptions
    <$> strOption (long "keypair" <> metavar "MY_KEYPAIR" <> value (unsafePerformIO defaultKeyPairPath))
    <*> strOption (long "secret" <> short 'i' <> metavar "SHARED_SECRET")

commandParser :: Parser Command
commandParser = subparser
    (  command "new" (info (GenerateKeyPair <$> generateKeyPairOptions) (progDesc "Create a new Key Pair"))
    <> command "share" (info (NewSecret <$> newSecretOptions) (progDesc "Share Safely files"))
    <> command "open" (info (ReadSecret <$> readSecretOptions) (progDesc "Unzip the given secret"))
    )

opts :: ParserInfo Command
opts = info (commandParser <**> helper)
    (  fullDesc
    <> progDesc "ShareSafe - Command line"
    <> header "sharesafe - create secret and encrypt files only your recipients can open"
    )

main :: IO ()
main = do
    cmd <- execParser opts
    runApp defaultAppState $ case cmd of
        NewSecret o -> mainNewSecret o
        ReadSecret o -> mainReadSecret o
        GenerateKeyPair gkpopts -> do
            _ <- newPassword
            kp <- keyPairGenerate
            writeKeyPair kp (gkpoOutput gkpopts)
            say $ "new key pair generated and store in `" <> fromList (gkpoOutput gkpopts)
                                                          <> "'."

data SecretPackage = SecretPackage [Commitment] [Share] [(FilePath, Ciphered ByteString)]

instance ToJSON SecretPackage where
    toJSON (SecretPackage cs s l) = object
        [ "commitments" .= cs
        , "shares" .= s
        , "contents" .= l
        ]
instance FromJSON SecretPackage where
    parseJSON = withObject "SecretPackage" $ \o -> SecretPackage
        <$> o .: "commitments"
        <*> o .: "shares"
        <*> o .: "contents"

zipSecret :: FilePath -> SecretPackage -> IO ()
zipSecret o = BL.writeFile o . compress . encode

unzipSecret :: FilePath -> IO SecretPackage
unzipSecret fp = do
    c <- eitherDecode . decompress <$> BL.readFile fp
    case c of
        Left err -> error $ "error while reading: " <> fp <> err
        Right a -> return a

mainReadSecret :: ReadSecretOptions -> App ()
mainReadSecret rso = do
    kp <- openKeyPair $ rsoMyPrivateKey rso
    SecretPackage commitments shares files <- liftIO $ unzipSecret $ rsoSecret rso
    s <- case find ((==) (toPublicKey kp) . sharePublicKey) shares of
            Nothing -> error "cannot find the share associated to you PrivateKey"
            Just a  -> return a
    unless (verifyShare commitments s) $ error "the does not match the commitments"
    ds <- recoverShare kp s
    let key = throwCryptoError $ recoverSecret [ds]
    forM_ files $ \(fn, content) -> liftIO $
        B.writeFile fn $ throwCryptoError $ decrypt' key header' content

mainNewSecret :: NewSecretOptions -> App ()
mainNewSecret nso = do
    kp <- openKeyPair $ myPrivateKey nso
    recipients <- forM (othersPublicKey nso) $ flip withPublicKey return
    let users = toPublicKey kp : recipients
    (s, commitments, ps) <- generateSecret 1 users
    l <- forM (toEncryptFiles nso) $ \file -> do
            content <- liftIO $ B.readFile file
            (file,) . throwCryptoError <$> encrypt' s header' content
    liftIO $ zipSecret (outputTo nso) $ SecretPackage commitments ps l

header' :: ByteString
header' = mempty
