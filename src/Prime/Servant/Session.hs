-- |
-- Module      : Prime.Servant.Session
-- License     : BSD-style
-- Maintainer  : Nicolas Di Prima <nicolas@primetype.co.uk>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Prime.Servant.Session
    ( mkFileKey
    , mkFileKeySet
    , mkRandomSource
    , FileKSParams(..)
    , FileKSState(..)
    ) where

import Foundation
import qualified Prelude
import Data.ByteArray.Encoding
import Control.Monad.Catch (MonadThrow)
import Control.Monad.IO.Class
import qualified Data.ByteString.Char8 as BSC8
import Servant.Server.Experimental.Auth.Cookie
import System.FilePath
import System.Directory (doesFileExist, getModificationTime, createDirectoryIfMissing, listDirectory, removeFile)
import Control.Monad
import Control.Concurrent (threadDelay)
import Data.List (sort)
import Data.Time.Clock (UTCTime(..))

import Prime.Common.Time

data FileKSParams = FileKSParams
  { fkspPath    :: LString
  , fkspMaxKeys :: Int
  , fkspKeySize :: Int
  }

data FileKSState = FileKSState
  { fkssLastModified :: UTCTime } deriving Eq

mkFileKey :: FileKSParams -> IO ()
mkFileKey FileKSParams {..} = (,) <$> mkName <*> mkKey >>= uncurry Prelude.writeFile
 where
  mkKey = generateRandomBytes fkspKeySize
    >>= return
      . BSC8.unpack
      . convertToBase Base64

  mkName = timeCurrent
    >>= return
      . (fkspPath </>)
      . (<.> "b64")
      . Prelude.show
    >>= \name -> do
      exists <- doesFileExist name
      if exists
      then (threadDelay 1000000) >> mkName
        -- ^ we don't want to change the keys that often
      else return name


mkFileKeySet :: (MonadIO m, MonadThrow m)
  => FileKSParams
  -> m (RenewableKeySet FileKSState FileKSParams)
mkFileKeySet = mkKeySet where

  mkKeySet FileKSParams {..} = do
    liftIO $ do
      createDirectoryIfMissing True fkspPath
      listDirectory fkspPath >>= \fs -> when (null fs) $
        mkFileKey FileKSParams {..}

    let fkssLastModified = UTCTime (toEnum 0) 0

    mkRenewableKeySet
      RenewableKeySetHooks {..}
      FileKSParams {..}
      FileKSState {..}

  rkshNewState :: (MonadIO m, MonadThrow m)
               => FileKSParams -> ([ServerKey], FileKSState) -> m ([ServerKey], FileKSState)
  rkshNeedUpdate FileKSParams {..} (_, FileKSState {..}) = do
    lastModified <- liftIO $ getModificationTime fkspPath
    return (lastModified > fkssLastModified)

  getLastModifiedFiles FileKSParams {..} = listDirectory fkspPath
    >>= return . Prelude.map (fkspPath </>)
    >>= \fs -> Prelude.zip <$> (Prelude.mapM getModificationTime fs) <*> (return fs)
    >>= return
      . Prelude.map snd
      . take fkspMaxKeys
      . Prelude.reverse
      . sort

  readKey = Prelude.fmap (either (error "wrong key format") id . convertFromBase Base64 . BSC8.pack) . Prelude.readFile

  rkshNewState FileKSParams {..} (_, s) = liftIO $ do
    lastModified <- liftIO $ getModificationTime fkspPath
    keys <- getLastModifiedFiles FileKSParams {..} >>= mapM readKey
    return (keys, s {fkssLastModified = lastModified})

  rkshRemoveKey :: (MonadIO m, MonadThrow m) => FileKSParams -> ServerKey -> m ()
  rkshRemoveKey FileKSParams {..} key = liftIO $ getLastModifiedFiles FileKSParams {..}
    >>= \fs -> Prelude.zip fs <$> Prelude.mapM readKey fs
    >>= return . Prelude.filter ((== key) . snd)
    >>= Prelude.mapM_ (removeFile . fst)
