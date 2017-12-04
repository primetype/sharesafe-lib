module Test.Prime.Common.NAR
    ( tests
    , testFromToNar
    ) where

import Control.Monad (replicateM)

import Foundation
import Foundation.Check
import Foundation.Conduit

import Prime.Common.NAR

data NarTestObj = NarTestObj
  { ntoHeader :: !NarHeader
  , ntoBlob1  :: !(UArray Word8)
  , ntoBlob2  :: !(UArray Word8)
  } deriving (Show, Eq, Typeable)
instance Arbitrary NarTestObj where
  arbitrary = do
    h <- pure 0x5d204852414e205b
    f <- pure 0
    b1sz <- between (0, 32)
    b1 <- fromList <$> replicateM (fromIntegral b1sz) arbitrary
    b2sz <- between (0, 32)
    b2 <- fromList <$> replicateM (fromIntegral b2sz) arbitrary
    pure $ NarTestObj
      { ntoHeader = NarHeader h f (fromIntegral b1sz) (fromIntegral b2sz)
      , ntoBlob1  = b1
      , ntoBlob2  = b2
      }

testFromToNar :: (IsNarItem obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
              => proxy obj
              -> Test
testFromToNar = Property "packNar .| unpackNar === id" . func
  where
    func :: (IsNarItem obj, Arbitrary obj, Eq obj, Show obj, Typeable obj)
         => proxy obj
         -> obj
         -> PropertyCheck
    func proxy a =
      a === runConduitPure (packNar a .| narSinkC .| narSourceC .| unpackNar proxy)

tests :: Test
tests = Group "NAR"
  [ Property "narSinkC (1)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 0 0, Blob (NarBlob1 mempty 0), Blob (NarBlob2 mempty 0)]
          r = runConduitPure (yields a .| narSinkC .| sinkList)
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ]
              ]
       in e === r
  , Property "narSinkC (2)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 4 0, Blob (NarBlob1 (replicate 4 15) 0), Blob (NarBlob2 mempty 0)]
          r = runConduitPure (yields a .| narSinkC .| sinkList)
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,4,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ]
              , fromList [15, 15, 15, 15], fromList [0,0,0,0]
              ]
       in e === r
  , Property "narSinkC (3)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 0 1, Blob (NarBlob1 mempty 0), Blob (NarBlob2 (singleton 15) 0)]
          r = runConduitPure (yields a .| narSinkC .| sinkList)
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ,1,0,0,0,0,0,0,0 ]
              , fromList [15], fromList [0,0,0,0,0,0,0]
              ]
       in e === r
  , Property "narSinkC (4)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 1 8, Blob (NarBlob1 (singleton 42) 0), Blob (NarBlob2 (replicate 8 0x0f) 0)]
          r = runConduitPure (yields a .| narSinkC .| sinkList)
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,1,0,0,0,0,0,0,0 ,8,0,0,0,0,0,0,0 ]
              , fromList [42], fromList [0,0,0,0,0,0,0]
              , replicate 8 0x0f, mempty
              ]
       in e === r
  , Property "narSinkC (5)" $
      let a = [ Header $ NarHeader 0x5d204852414e205b 0 1 8
              , Blob (NarBlob1 (singleton 42) 0)
              , Blob (NarBlob2 (replicate 8 0x0f) 0)
              , Header $ NarHeader 0x5d204852414e205b 1 2 2
              , Blob (NarBlob1 (replicate 2 0x0f) 0)
              , Blob (NarBlob2 (replicate 2 0x0f) 0)
              ]
          r = runConduitPure (yields a .| narSinkC .| sinkList)
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,1,0,0,0,0,0,0,0 ,8,0,0,0,0,0,0,0 ]
              , fromList [42], fromList [0,0,0,0,0,0,0]
              , replicate 8 0x0f, mempty
              , fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 1,0,0,0,0,0,0,0 ,2,0,0,0,0,0,0,0 ,2,0,0,0,0,0,0,0 ]
              , replicate 2 0x0f, replicate 6 0
              , replicate 2 0x0f, replicate 6 0
              ]
       in e === r
  , Property "narSourceC (1)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 0 0, Blob (NarBlob1 mempty 0), Blob (NarBlob2 mempty 0)]
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ]
              ]
          r = runConduitPure (yields e .| narSourceC .| sinkList)
       in a === r
  , Property "narSourceC (2)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 4 0, Blob (NarBlob1 (replicate 4 15) 0), Blob (NarBlob2 mempty 0)]
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,4,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ]
              , fromList [15, 15, 15, 15], fromList [0,0,0,0]
              ]
          r = runConduitPure (yields e .| narSourceC .| sinkList)
       in a === r
  , Property "narSourceC (3)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 0 1, Blob (NarBlob1 mempty 0), Blob (NarBlob2 (singleton 15) 0)]
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,0,0,0,0,0,0,0,0 ,1,0,0,0,0,0,0,0 ]
              , fromList [15], fromList [0,0,0,0,0,0,0]
              ]
          r = runConduitPure (yields e .| narSourceC .| sinkList)
       in a === r
  , Property "narSourceC (4)" $
      let a = [Header $ NarHeader 0x5d204852414e205b 0 1 8, Blob (NarBlob1 (singleton 42) 0), Blob (NarBlob2 (replicate 8 0x0f) 0)]
          e = [ fromList [0x5b, 0x20, 0x4e, 0x41, 0x52, 0x48, 0x20, 0x5d, 0,0,0,0,0,0,0,0 ,1,0,0,0,0,0,0,0 ,8,0,0,0,0,0,0,0 ]
              , fromList [42], fromList [0,0,0,0,0,0,0]
              , replicate 8 0x0f, mempty
              ]
          r = runConduitPure (yields e .| narSourceC .| sinkList)
       in a === r
  , Property "narSinkC .| narSourceC === id" $ \(NarTestObj h b1 b2) ->
      let a = [Header h, Blob (NarBlob1 b1 0), Blob (NarBlob2 b2 0)]
       in a === runConduitPure (yields a .| narSinkC .| narSourceC .| sinkList)
  ]
