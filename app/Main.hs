{-# LANGUAGE CPP #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import qualified Prelude
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import Prime.Common.Base
import Prime.Common.PEM
import Prime.Common.JSON
import Prime.Common.Conduit
import Prime.Common.NAR
import Prime.Secret

import Data.Version (Version(..))
import Data.List (zip)
import Control.Monad (forM, forM_, mapM_)
import Text.Read (readEither)
import GHC.IO.Handle (Handle, hSetBuffering, BufferMode(NoBuffering), hGetLine, hSetEcho, hGetEcho)
import Foundation.IO
import Foundation.Monad
import Foundation.VFS.Path ((</>))
import Foundation.VFS.FilePath (filePathToLString, FilePath)
import Data.Maybe (fromMaybe)
import System.FilePath ((-<.>))
import System.Directory

import Console.Options

main :: IO ()
main = defaultMain $ do
  programName "sharesafe"
  programVersion $ Version [0,1] ["alpha"]
  programDescription "ShareSafe: create and share secrets"

  command "cipher" cipherSubProgram
  command "pvss" pvssSubProgram
  command "key" keySubProgram

  command "list" listLocalStoreKeys
  command "add" addKeyPairToLocalStore
  command "encrypt" encryptWithLocalStore
  command "decrypt" decryptWithLocalStore

-- -------------------------------------------------------------------------- --
--                      Convenient cmds                                       --
-- -------------------------------------------------------------------------- --

addKeyPairToLocalStore :: OptionDesc (IO ()) ()
addKeyPairToLocalStore = do
    description "Add a given keypair to the local store."
    name <- argument "ALIAS" Right
    file <- argument "FILE" (Right . fromString)
    action $ \get ->
        withFile (get file) ReadMode $ \s ->
        withContactFile (get name) $ \path ->
        withFile path WriteMode $ \d ->
            runConduit $ sourceHandle s .| sinkHandle d

listLocalStoreKeys :: OptionDesc (IO ()) ()
listLocalStoreKeys = do
  description "list public alias with their associated public keys"
  action $ \_ -> withContacts $ mapM_ putStrLn

encryptWithLocalStore :: OptionDesc (IO ()) ()
encryptWithLocalStore = do
    description "encrypt a file"
    pkssf <- flagMany $ flagParam (FlagShort 'p' <> FlagLong "participant" <> FlagDescription "name of the participant from contact list")
                                  (FlagRequired Right)
    thresholdf <-      flagParam (FlagShort 't' <> FlagLong "threshold" <> FlagDescription "Threshold to retrive the secrets (default: 1)")
                                 (FlagRequired readEither)
    inf     <-         flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "Where to read the file to share (default STDIN)")
                                 (FlagRequired (Right . fromString))
    outf    <-         flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the shared file (default STDOUT)")
                                 (FlagRequired (Right . fromString))
    action $ \toParam -> do
        -- retrieve the threshold
        let threshold = fromMaybe 1 $ toParam thresholdf
        -- retrieve the keys
        let pkss = toParam pkssf
        apks <- forM pkss $ \contact -> withContactKey contact $ \key _-> pure key
        unless (Prelude.length apks >= fromInteger threshold) $
            error "threshold is higher than number of participants"

        (key, commitments, shares) <- generateSecret threshold apks

        nonce <- throwCryptoError <$> mkNonce

        withFileOr (toParam outf) WriteMode stdout $ \handleOut ->
          withFileOr (toParam inf) ReadMode stdin  $ \handleIn -> do
            b <- runConduit $ sourceHandle handleIn .| encryptC' key header nonce .| sinkList
            runConduit $ (packNar commitments >> mapM_ packNar shares >> packNar (mconcat b))
                      .| narSinkC
                      .| sinkHandle handleOut

decryptWithLocalStore :: OptionDesc (IO ()) ()
decryptWithLocalStore = do
    description "decrypt a share"

    pkssf <- flagMany $ flagParam (FlagShort 'p' <> FlagLong "participant" <> FlagDescription "name of the participant from contact list")
                                  (FlagRequired Right)
    inf     <-         flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "Where to read the file to share (default STDIN)")
                                 (FlagRequired (Right . fromString))
    outf    <-         flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the shared file (default STDOUT)")
                                 (FlagRequired (Right . fromString))
    action $ \toParam -> do
        -- retrieve the keys
        let pkss = toParam pkssf
        hSetBuffering stdin  NoBuffering
        hSetBuffering stdout NoBuffering
        echoing <- hGetEcho stdin
        hSetEcho stdin False
        apks <- forM pkss $ \contact -> withContactKey contact $ \pk pppks -> do
                    putStr $ fromList $ "password for " <> contact <> ": "
                    -- let pwd = mempty
                    pwd <- either error id . parsePasswordParam <$> hGetLine stdin
                    putStrLn ""
                    flip KeyPair pk <$> throwCryptoErrorIO (recover pwd pppks)
        hSetEcho stdin echoing

        withFileOr (toParam outf) WriteMode stdout $ \handleOut ->
          withFile (fromMaybe (error "missing input file") $ toParam inf) ReadMode $ \handleIn ->
            runConduit $ sourceHandle handleIn
                      .| narSourceC
                      .| parseEncFile apks
                      .| sinkHandle handleOut
  where
    parseEncFile users = do
        Just commitments <- unpackNar (Proxy @[Commitment])
        unlocked <- go mempty
        Just b <- unpackNar (Proxy @(UArray Word8))
        yield b .| decryptC' unlocked header
      where
        go acc = do
            mshare <- unpackNar (Proxy @Share)
            case mshare of
                Nothing -> finalize acc
                Just s  -> case getUserKeyPair s of
                    Nothing -> go acc
                    Just kp -> do
                        os <- liftIO $ recoverShare kp s
                        go (os : acc)
        getUserKeyPair s = find (\kp -> sharePublicKey s == toPublicKey kp) users
        finalize acc =
            case recoverSecret acc of
                CryptoPassed a -> pure a
                CryptoFailed err -> error $ "failed to recover the secret: " <>  show err

{-
unlockShareWithSubProgram :: OptionDesc (IO ()) ()
unlockShareWithSubProgram = do
    description "unlock one of the share from a given share (see: `share new` command)"
    selff <-            flagParam (FlagShort 's' <> FlagLong "self" <> FlagDescription "alias of the public key to use (default: main)")
                                  (FlagRequired Right)
    pwd <- flagParam (FlagShort 'p' <> FlagLong "password" <> FlagDescription "Password protecting the generated private key")
                     (FlagRequired parsePasswordParam)
    inf     <-         flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "Where to read the file to share (default STDIN)")
                                 (FlagRequired (Right . fromString))
    outf    <-         flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the shared file (default STDOUT)")
                                 (FlagRequired (Right . fromString))
    action $ \toParam -> do
        spk <- withSelfPublicKey (fromMaybe "main" $ toParam selff) return
        let password = fromMaybe mempty (toParam pwd)

        let storeInfos = do
              commitments <- await -- the commitments
              shares <- await
              return (commitments, shares)

        withFileOr (toParam inf) ReadMode stdin $ \hIn -> do
          runConduit $ sourceHandle hIn
                    .| narSourceC
                    .| handleStuff spk password
  where
    handleStuff pk pwd = do
      undefined
-}

-- -------------------------------------------------------------------------- --

withContactKey :: LString -> (PublicKey -> PasswordProtected PrivateKey -> IO a) -> IO a
withContactKey contact f = withContactFile contact $ \path ->
    withFile path ReadMode $ flip withPPKeyPair f

withContactFile :: LString -> (FilePath -> IO a) -> IO a
withContactFile contact f = withContactDir $ \dir -> do
  let path = dir </> fromString contact
  mkFileIfNotExist path
  f path

withContacts :: ([String] -> IO a) -> IO a
withContacts f = withContactDir $ \dir ->
    f . fmap fromList =<< listDirectory (filePathToLString dir)

withContactDir :: (FilePath -> IO a) -> IO a
withContactDir f = withDataDirectory $ \dir -> do
  let path = dir </> "contact"
  createDirectoryIfMissing True (filePathToLString path)
  f path

mkFileIfNotExist :: FilePath -> IO ()
mkFileIfNotExist path = do
  exists <- doesFileExist (filePathToLString path)
  unless exists $ Prelude.writeFile (filePathToLString path) ""

withDataDirectory :: (FilePath -> IO a) -> IO a
withDataDirectory f = do
  dir <- getXdgDirectory XdgData "sharesafe"
  createDirectoryIfMissing True dir
  f $ fromString dir

-- -------------------------------------------------------------------------- --
--                      Secret Sharing                                        --
-- -------------------------------------------------------------------------- --

pvssSubProgram :: OptionDesc (IO ()) ()
pvssSubProgram = do
  description "PVSS operations"
  pvssRecoverSubProgram
  pvssOpenShareSubProgram
  pvssVerifyShareSubProgram
  pvssNewShareSubProgram

pvssNewShareSubProgram :: OptionDesc (IO ()) ()
pvssNewShareSubProgram = command "new" $ do
    description "generate a new share secret. The Participant's shares are generated based on the participants's public key filename. (filename -<.> secret-share)"
    pkssf <- flagMany $ flagParam (FlagShort 'p' <> FlagLong "participant" <> FlagDescription "Public key of the participants")
                                  (FlagRequired (Right . fromString))
    thresholdf <-      flagParam (FlagShort 't' <> FlagLong "threshold" <> FlagDescription "Threshold to retrive the secrets (default: 1)")
                                 (FlagRequired readEither)
    commitmentf <-     flagParam (FlagShort 'c' <> FlagLong "commitments" <> FlagDescription "Where to write the commitments")
                                 (FlagRequired (Right . fromString))
    outf    <-         flagParam (FlagShort 'o' <> FlagLong "secret" <> FlagDescription "Where to write the secret (default STDOUT)")
                                 (FlagRequired (Right . fromString))
    action $ \toParam -> do
        -- retrieve the threshold
        let threshold = fromMaybe 1 $ toParam thresholdf
        -- retrieve the keys
        let pkss = toParam pkssf
        pks <- forM pkss $ \pksf -> do
                  bytes <- convert <$> readFile pksf
                  let e = flip fromPEM bytes $ flip findPem (Proxy :: Proxy PublicKey)
                  case e of
                      Left err -> fail $ "keypair error: " <> err
                      Right Nothing -> fail "Cannot find PEM"
                      Right (Just pemPk) -> return $ convert $ pemContent pemPk
        (ek, commitments, shares) <- generateSecret threshold pks

        forM_ (toParam commitmentf) $ \fp -> withFile fp WriteMode $ flip hPut (convert $ encodeJSON commitments)
        withFileOr (toParam outf) WriteMode stdout $ \h ->
          hPut h (B.convertToBase B.Base64 ek)
        forM_ (zip pkss shares) $ \(fp, share) ->
          let fp' = fromString $ filePathToLString fp -<.> "secret-share"
           in withFile fp' WriteMode $ flip hPut (convert $ encodeJSON share)

pvssVerifyShareSubProgram :: OptionDesc (IO ()) ()
pvssVerifyShareSubProgram = command "verify" $ do
    description "verify the given share against the commitments."
    sharef <- flagParam (FlagShort 's' <> FlagLong "share" <> FlagDescription "Share to verify participant")
                                  (FlagRequired (Right . fromString))
    commitmentf <-     flagParam (FlagShort 'c' <> FlagLong "commitments" <> FlagDescription "Where to write the commitments")
                                 (FlagRequired (Right . fromString))
    action $ \toParam -> do
      let sharefp = fromMaybe (error "no share provided") (toParam sharef)
      let commitmentfp = fromMaybe (error "no commitment provided") (toParam commitmentf)

      share <- either error id . baParseJSON <$> readFile sharefp
      commitments <- either error id . baParseJSON <$> readFile commitmentfp

      unless (verifyShare commitments share) $ error "invalid share"

pvssOpenShareSubProgram :: OptionDesc (IO ()) ()
pvssOpenShareSubProgram = command "reveal-share" $ do
    description "open the given share"
    sharef <- flagParam (FlagShort 's' <> FlagLong "share" <> FlagDescription "Share to verify participant")
                                  (FlagRequired (Right . fromString))
    pwd <- flagParam (FlagShort 'p' <> FlagLong "password" <> FlagDescription "New Password to protect the private key")
                      (FlagRequired parsePasswordParam)
    keyf <- flagParam (FlagShort 'k' <> FlagLong "key" <> FlagDescription "read the private key from")
                     (FlagRequired (Right . fromString))
    out <- flagParam (FlagShort 'o' <> FlagLong "out" <> FlagDescription "read the private key from")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
      let sharefp = fromMaybe (error "no share provided") (toParam sharef)
      let keyfp = fromMaybe (error "no key provided") (toParam keyf)
      let password = fromMaybe mempty $ toParam pwd

      kp <- withFile keyfp ReadMode $ \h -> withKeyPair password h return
      share <- either error id . baParseJSON <$> readFile sharefp

      es <- recoverShare kp share

      withFileOr (toParam out) WriteMode stdout $ \h ->
        hPut h (convert (binToBase64 es))

pvssRecoverSubProgram :: OptionDesc (IO ()) ()
pvssRecoverSubProgram = command "recover" $ do
    description "retrieve the shared secret"
    sharesf <- flagMany $ flagParam (FlagShort 's' <> FlagLong "share" <> FlagDescription "decrypted share files")
                                    (FlagRequired (Right . fromString))
    outf <- flagParam (FlagShort 'o' <> FlagLong "out" <> FlagDescription "where to write the secret (default: STDOUT)")
                      (FlagRequired (Right . fromString))
    action $ \toParam -> do
        -- retrieve the shares
        let shares = toParam sharesf
        xshare <- forM shares $ \x ->
                    case binFromBase64 (fromString x :: String) of
                      Left err -> fail $ "share encoded error: " <> err
                      Right e  -> return e
        ek <- case recoverSecret xshare of
                CryptoPassed a -> pure a
                CryptoFailed err -> error $ "failed to recover the secret: " <>  show err

        withFileOr (toParam outf) WriteMode stdout $ \h ->
          hPut h (B.convertToBase B.Base64 ek)

-- -------------------------------------------------------------------------- --
--                      Share Safe Ciphers                                    --
-- -------------------------------------------------------------------------- --

cipherSubProgram :: OptionDesc (IO ()) ()
cipherSubProgram = do
  description "encrypt/decrypt data using PVSS's key or generating new one."

  cipherEncryptSubProgram
  cipherDecryptSubProgram

cipherEncryptSubProgram :: OptionDesc (IO ()) ()
cipherEncryptSubProgram = command "encrypt" $ do
    description "cipher with the given encryption key"
    keyf <- flagParam (FlagShort 'k' <> FlagLong "key" <> FlagDescription "encryption key to cipher data with")
                      (FlagRequired parseEncryptionKey)
    inf <- flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "the input file to encrypt (default: STDIN)")
                     (FlagRequired (Right . fromString))
    out <- flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "the output (ciphered) default: STDOUT (raw)")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
        let key = fromMaybe (error "expecting base64 encoded encryption key") (toParam keyf)
        nonce <- throwCryptoError <$> mkNonce
        withFileOr (toParam inf) ReadMode stdin  $ \handleIn ->
         withFileOr (toParam out) WriteMode stdout $ \handleOut ->
          runConduit $ sourceHandle handleIn .| encryptC' key header nonce .| sinkHandle handleOut

cipherDecryptSubProgram :: OptionDesc (IO ()) ()
cipherDecryptSubProgram = command "decrypt" $ do
    description "cipher with the given encryption key"
    keyf <- flagParam (FlagShort 'k' <> FlagLong "key" <> FlagDescription "encryption key to cipher data with")
                      (FlagRequired parseEncryptionKey)
    inf <- flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "the input file to decrypt (default: STDIN)")
                     (FlagRequired (Right . fromString))
    out <- flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "the output (clear) default: STDOUT (raw)")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
        let key = fromMaybe (error "expecting base64 encoded encryption key") (toParam keyf)
        withFileOr (toParam inf) ReadMode stdin  $ \handleIn ->
         withFileOr (toParam out) WriteMode stdout $ \handleOut ->
          runConduit $ sourceHandle handleIn .| decryptC' key header .| sinkHandle handleOut

header :: String
header = "some header"

-- -------------------------------------------------------------------------- --
--                      Key Genration Manipulation                            --
-- -------------------------------------------------------------------------- --

keySubProgram :: OptionDesc (IO ()) ()
keySubProgram = do
  description "generate new private key, get the public key from the given private key..."
  keyGenerateSubProgram
  keyChangePasswordSubProgram
  keyExportPublicKey

keyGenerateSubProgram :: OptionDesc (IO ()) ()
keyGenerateSubProgram = command "new" $ do
    description "generate a new private key"
    pwd <- flagParam (FlagShort 'p' <> FlagLong "password" <> FlagDescription "Password protecting the generated private key")
                     (FlagRequired parsePasswordParam)
    out <- flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the new generated private key")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
        let password = fromMaybe mempty $ toParam pwd
        kp <- keyPairGenerate
        pks <- throwCryptoErrorIO =<< protect password (toPrivateKey kp)
        let pemSk = toPEM pks
        let pemPk = toPEM (toPublicKey kp)
        withFileOr (toParam out) WriteMode stdout $ flip hPut (convert $ pemSk <> pemPk)

keyChangePasswordSubProgram :: OptionDesc (IO ()) ()
keyChangePasswordSubProgram = command "change-password" $ do
    description "change the password of the given private key"
    ppwd <- flagParam (FlagShort 'p' <> FlagLong "old-password" <> FlagDescription "Password protecting the private key")
                      (FlagRequired parsePasswordParam)
    npwd <- flagParam (FlagShort 'n' <> FlagLong "password" <> FlagDescription "New Password to protect the private key")
                      (FlagRequired parsePasswordParam)
    inf <- flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "read the private key from (default=STDIN)")
                     (FlagRequired (Right . fromString))
    out <- flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the private key (default=INPUT or STDOUT)")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
        -- get the password
        let oldPassword = fromMaybe mempty $ toParam ppwd
        let newPassword = fromMaybe mempty $ toParam npwd
        -- retrieve the keys
        kp <- withFileOr (toParam inf) ReadMode stdin $
                  \h -> withKeyPair oldPassword h return
        -- key with new password
        pks <- throwCryptoErrorIO =<< protect newPassword (toPrivateKey kp)

        let pemSk = toPEM pks
        let pemPk = toPEM (toPublicKey kp)

        withFileOr (toParam out <|> toParam inf) WriteMode stdout $ flip hPut (convert $ pemSk <> pemPk)

keyExportPublicKey :: OptionDesc (IO ()) ()
keyExportPublicKey = command "export-public" $ do
    description "export the public key of the given of the given private key"
    inf <- flagParam (FlagShort 'i' <> FlagLong "input" <> FlagDescription "read the private key from (default=STDIN)")
                     (FlagRequired (Right . fromString))
    out <- flagParam (FlagShort 'o' <> FlagLong "output" <> FlagDescription "Where to write the private key (default=INPUT or STDOUT)")
                     (FlagRequired (Right . fromString))
    action $ \toParam -> do
        pk <- withFileOr (toParam inf) ReadMode stdin $ flip withPublicKey return
        let pemPk = toPEM pk
        withFileOr (toParam out) WriteMode stdout $ flip hPut (convert pemPk)

-- -------------------------------------------------------------------------- --
--                      Helpers                                               --
-- -------------------------------------------------------------------------- --

parsePasswordParam :: LString -> Either LString Password
parsePasswordParam = Right . B.convert . f
  where
    f :: LString -> String
    f = fromString

parseEncryptionKey :: LString -> Either LString EncryptionKey
parseEncryptionKey str =
    case B.convertFromBase B.Base64 $ f str of
      Left err -> Left err
      Right sbs -> case encryptionKey sbs of
        CryptoFailed err -> Left (show err)
        CryptoPassed a   -> Right a
  where
    f :: LString -> String
    f = fromString

withFileOr :: Maybe FilePath -> IOMode -> Handle -> (Handle -> IO a) -> IO a
withFileOr Nothing   _    h f = f h
withFileOr (Just fp) mode _ f = withFile fp mode f

withPPKeyPair :: Handle -> (PublicKey -> PasswordProtected PrivateKey -> IO a) -> IO a
withPPKeyPair h f = do
  bytes <- B.convert <$> hGet h 1024
  let e = flip fromPEM bytes $ \l -> (,)
            <$> findPem l (Proxy :: Proxy PublicKey)
            <*> findPem l (Proxy :: Proxy (PasswordProtected PrivateKey))
  case e of
      Left err -> fail $ "keypair error: " <> err
      Right Nothing -> fail "Cannot find PEM"
      Right (Just (pemPk, pemPppk)) ->
        let pk    = convert $ pemContent pemPk
            pppks = convert $ pemContent pemPppk
         in f pk pppks

withKeyPair :: Password -> Handle -> (KeyPair -> IO a) -> IO a
withKeyPair pwd h f = withPPKeyPair h $ \pk pppks -> do
    sk <- throwCryptoErrorIO $ recover pwd pppks
    f $ KeyPair sk pk

withPublicKey :: Handle -> (PublicKey -> IO a) -> IO a
withPublicKey h f = do
  bytes <- B.convert <$> hGet h 1024
  let e = flip fromPEM bytes $ \l -> findPem l (Proxy :: Proxy PublicKey)
  case e of
      Left err -> fail $ "keypair error: " <> err
      Right Nothing -> fail "Cannot find PEM"
      Right (Just pemPk) -> f $ convert $ pemContent pemPk
