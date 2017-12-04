{-# LANGUAGE AllowAmbiguousTypes #-}

module Prime.Common.NAR
    ( NarHeader(..)
    , NarBlob(..)
    , NarObj(..)
    , narSourceC
    , narSinkC
    , IsNarItem(..)
    , awaitBlob1, awaitBlob2
    ) where

import Foundation.Primitive (unLE, toLE)
import Foundation.Array.Internal (recast)
import Prime.Common.Base
import Prime.Common.Conduit

class IsNarItem item where
    magicNar  :: Word64
    packNar   :: Monad m =>       item -> Conduit     () NarObj m   ()
    unpackNar :: Monad m => proxy item -> Conduit NarObj     () m item

data NarHeader = NarHeader
    { narHeaderSignature :: !Word64
    , narHeaderFlags     :: !Word64
    , narHeaderSize1     :: !Word64
    , narHeaderSize2     :: !Word64
    }
  deriving (Show, Eq, Ord, Typeable)

data NarBlob
    = NarBlob1
        { narBlobData   :: !(UArray Word8)
        , narBlobRemain :: !(CountOf Word8)
        }
    | NarBlob2
        { narBlobData   :: !(UArray Word8)
        , narBlobRemain :: !(CountOf Word8)
        }
  deriving (Show, Eq, Ord, Typeable)

data NarObj = Header !NarHeader | Blob !NarBlob
  deriving (Show, Eq, Ord, Typeable)

awaitBlob1 :: Monad m => Conduit NarObj out m (Maybe (UArray Word8))
awaitBlob1 = do
    m <- await
    case m of
      Just (Blob (NarBlob1 b sz)) -> Just <$> go b sz
      _                           -> return Nothing
  where
    go front 0 = pure front
    go front n = do
      m <- await
      case m of
        Just (Blob (NarBlob1 b sz)) -> go (front <> b) sz
        _                           -> error $ "missing " <> show n <> " bytes"

awaitBlob2 :: Monad m => Conduit NarObj out m (Maybe (UArray Word8))
awaitBlob2 = do
  m <- await
  case m of
    Just (Blob (NarBlob2 b sz)) -> Just <$> go b sz
    _                           -> return Nothing
  where
    go front 0 = pure front
    go front n = do
      m <- await
      case m of
        Just (Blob (NarBlob2 b sz)) -> go (front <> b) sz
        _                           -> error $ "missing " <> show n <> " bytes"

narSinkC :: Monad m => Conduit NarObj (UArray Word8) m ()
narSinkC = do
  m <- await
  case m of
    Nothing -> return ()
    Just (Blob   _)  -> error "Expecting Nar Header first"
    Just (Header nh) -> do
      yield $ recast $ fromList $ toLE <$> [narHeaderSignature nh, narHeaderFlags nh, narHeaderSize1 nh, narHeaderSize2 nh]
      narSinkBlob1C $ fromIntegral $ narHeaderSize1 nh
      narSinkBlob2C $ fromIntegral $ narHeaderSize2 nh
      narSinkC

narSinkBlob1C :: Monad m => CountOf Word8 -> Conduit NarObj (UArray Word8) m ()
narSinkBlob1C 0 = do
    m <- await
    case m of
      Just (Blob (NarBlob1 _ 0)) -> return ()
      Nothing -> return ()
      _ -> error "invalid"
narSinkBlob1C n = do
    go n
    let x = fromCount n `mod` 8
        n' = toCount $ if x == 0 then 0 else 8 - x
    yield $ replicate n' 0x00
 where
   go :: Monad m => CountOf Word8 -> Conduit NarObj (UArray Word8) m ()
   go 0 = return ()
   go _ = do
     b <- await
     case b of
       Nothing -> return ()
       Just (Header _) -> error "Expecting a blob"
       Just (Blob (NarBlob1 arr r)) -> yield arr *> go r
       Just v@(Blob  NarBlob2{})    -> leftover v

narSinkBlob2C :: Monad m => CountOf Word8 -> Conduit NarObj (UArray Word8) m ()
narSinkBlob2C 0 = do
    m <- await
    case m of
      Just (Blob (NarBlob2 _ 0)) -> return ()
      Nothing -> return ()
      _ -> error "invalid"
narSinkBlob2C n = do
    go n
    let x = fromCount n `mod` 8
        n' = toCount $ if x == 0 then 0 else 8 - x
    yield $ replicate n' 0x00
 where
   go :: Monad m => CountOf Word8 -> Conduit NarObj (UArray Word8) m ()
   go 0 = return ()
   go _ = do
     b <- await
     case b of
       Nothing -> return ()
       Just (Header _) -> error "Expecting a blob"
       Just (Blob (NarBlob2 arr r)) -> yield arr *> go r
       Just (Blob  NarBlob1{})      -> error "cannot receive blob1 after blob2"

narSourceC :: Monad m => Conduit (UArray Word8) NarObj m ()
narSourceC = do
    mh <- narSourceHeaderC
    case mh of
        Nothing -> return ()
        Just h  -> do
            yield (Header h)
            narSourceContentC (fromIntegral $ narHeaderSize1 h) NarBlob1
            narSourceContentC (fromIntegral $ narHeaderSize2 h) NarBlob2
            narSourceC

narSourceHeaderC :: Monad m => Conduit (UArray Word8) out m (Maybe NarHeader)
narSourceHeaderC = do
    mba <- awaitBytes 32
    pure $ case recast <$> mba of
        Nothing -> Nothing
        Just ba -> do
            let [s,f,l1,l2] = unLE <$> toList ba
             in Just $ NarHeader s f l1 l2

narSourceContentC :: Monad m
                  => CountOf Word8
                  -> (UArray Word8 -> CountOf Word8 -> NarBlob)
                  -> Conduit (UArray Word8) NarObj m ()
narSourceContentC n mkBlob = do
    narSourceContentC' n mkBlob
    let x = fromCount n `mod` 8
        n' = if x == 0 then 0 else 8 - x
    m <- awaitBytes n'
    case m of
      Nothing -> error $ "needed " <> show n' <> " extra bytes"
      Just _  -> return ()

narSourceContentC' :: Monad m
                   => CountOf Word8
                   -> (UArray Word8 -> CountOf Word8 -> NarBlob)
                   -> Conduit (UArray Word8) NarObj m ()
narSourceContentC' n mkBlob
    | n == 0    = yield (Blob $ mkBlob mempty 0)
    | otherwise = go n
  where
    go 0 = return ()
    go l = do
        mba <- awaitUpTo l
        case mba of
            Nothing -> return ()
            Just b  | length b == 0 -> error "huh...."
                    | otherwise     -> do
                let remaining = fromMaybe 0 $ l - length b
                yield (Blob $ mkBlob b remaining)
                go remaining
