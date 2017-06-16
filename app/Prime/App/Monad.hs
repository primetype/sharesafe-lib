{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Prime.App.Monad
    ( App
    , runApp
    , AppState(..)
    , defaultAppState
    , CompletionMode(..)
    , setCompletionMode
    , get, put, withState
    , mFail
    , runHL
    , liftIO
    , defaultKeyPairPath
    , say
    ) where

import Prelude (error)

import Foundation.Monad hiding (mFail)
import Foundation.Monad.State (StateT, MonadState(..), runStateT, put)
import qualified Foundation.Monad.State as State
import qualified Foundation.Monad as M

import           System.Console.Haskeline hiding (getPassword)

import Prime.Common.Base
import System.Directory
import System.FilePath

import Prime.Secret (KeyPair, Password, MonadRandom(..))

runApp :: AppState -> App a -> IO a
runApp st app = fst <$> runStateT (runApp_ app) st

newtype App a = App
    { runApp_ :: StateT AppState IO a }
  deriving (Functor, Applicative, Monad, MonadIO)

instance MonadState App where
    type State App = AppState
    withState = App . withState

instance MonadFailure App where
    type Failure App = LString
    mFail = liftIO . error

instance MonadRandom App where
    getRandomBytes = liftIO . getRandomBytes

data AppState = AppState
    { userKeyPair  :: !(Maybe KeyPair)
    , userPassword :: !(Maybe Password)
    , completions  :: !CompletionMode
    }

defaultKeyPairPath :: MonadIO io => io FilePath
defaultKeyPairPath = flip (</>) "keypair.pem" <$> liftIO (getXdgDirectory XdgData "sharesafe")

defaultAppState :: AppState
defaultAppState = AppState
    { userKeyPair = Nothing
    , userPassword = Nothing
    , completions  = CompleteFiles
    }

get :: MonadState m => (State m -> a) -> m a
get f = f <$> State.get

mFail :: MonadFailure m => Failure m -> m a
mFail f = M.mFail f >> undefined

data CompletionMode = CompleteFiles | CompleteCommands [Completion]

setCompletionMode :: CompletionMode -> App ()
setCompletionMode cm = withState $ \s -> ((), s { completions = cm })

runHL :: InputT IO a -> App a
runHL cmd = do
    cm <- get completions
    liftIO $ case cm of
        CompleteFiles -> runInputT defaultSettings cmd
        CompleteCommands l ->
            runInputT (setComplete (mkListComplete l) defaultSettings) cmd
  where
    mkListComplete :: [Completion] -> CompletionFunc IO
    mkListComplete l (left, _) =
      return (mempty, filter (isPrefixOf (reverse left) . replacement) l)

say :: MonadIO m => String -> m ()
say = liftIO . putStrLn
