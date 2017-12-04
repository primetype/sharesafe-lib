module Prime.Common.Conduit
    ( module X
    , awaitBytes
    , awaitUpTo
    , awaitBase
    ) where

import Data.ByteArray as B
import Data.ByteArray.Encoding as B
import Prime.Common.Base
import qualified Foundation.Collection as C
import Foundation.Conduit as X
import Foundation.Conduit.Textual as X
import Foundation.Monad (MonadThrow(..))

awaitBytes :: ByteArray ba => Int -> Conduit ba out m (Maybe ba)
awaitBytes n = go mempty
  where
    go front = do
      mbs <- await
      case mbs of
        Nothing | B.length front /= n -> return Nothing
                | otherwise           -> return (Just front)
        Just bs -> do
          let bs' = front <> bs
          if B.length bs' > n
            then do
              let (x, y) = B.splitAt n bs'
              leftover y
              return $ Just x
            else go bs'

awaitUpTo :: Sequential ba => CountOf (C.Element ba) -> Conduit ba out m (Maybe ba)
awaitUpTo n
    | n == 0    = return Nothing
    | otherwise = go mempty
  where
    go front = do
        mbs <- await
        case mbs of
            Nothing | C.null front -> return Nothing
                    | otherwise    -> return (Just front)
            Just bs -> do
                let (x, y) = C.splitAt n $ front <> bs
                leftover y
                return $ Just x

newtype BaseError = BaseError LString
  deriving (Show, Typeable)
instance Exception BaseError

awaitBase :: (MonadThrow m, ByteArrayAccess input, ByteArray output) => B.Base -> Conduit input output m ()
awaitBase base = do
  minput <- await
  case minput of
    Nothing -> return ()
    Just bs | B.null bs -> awaitBase base
            | otherwise ->
      case B.convertFromBase base bs of
        Left err -> throw $ BaseError err
        Right a  -> yield a *> awaitBase base
