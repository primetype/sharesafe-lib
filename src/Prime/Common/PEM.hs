{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ConstraintKinds #-}

module Prime.Common.PEM
    ( HasPEM(..)
    , IsPEMSafe
    , PEM, pemContent
    , pemProxy
    , pemSave
    , pemRead
    , findPem
    ) where

import Prime.Common.Base
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.PEM hiding (pemName)
import qualified Data.PEM as PEM
import GHC.TypeLits

class HasPEM a where
    type PEMSafe a :: Bool
    type PEMSafe a = 'False

    pemName :: a -> LString
    pemHeaders :: a -> [(LString, ByteString)]

type IsPEMSafe a = IsPEMSafeType (PEMSafe a) a ~ 'True

type family IsPEMSafeType a b where
  IsPEMSafeType 'True  b = 'True
  IsPEMSafeType 'False b = TypeError
    (     ('Text "You are trying to write into a PEM an object that is not PEM Safe")
    ':$$: ('Text "The object of type " ':<>: 'ShowType b ':<>: 'Text " is not PEMSafe")
    ':$$: ('Text "It means it might not be wise to store this object.")
    )

pemProxy :: HasPEM a => proxy a -> (a -> b) -> b
pemProxy _ f = f undefined

pemSave :: (ByteArrayAccess a, HasPEM a, IsPEMSafe a)
        => LString -> a -> IO ()
pemSave fp a =
    B.appendFile fp $ pemWriteBS $
        PEM (pemName a) (pemHeaders a) (convert a)

pemRead :: LString -> ([PEM] -> a) -> IO (Either LString a)
pemRead fp f = fmap f . pemParseBS <$> B.readFile fp

findPem :: HasPEM a => [PEM] -> proxy a -> Maybe PEM
findPem l = findPem' undefined
  where
    findPem' :: HasPEM a => a -> proxy a -> Maybe PEM
    findPem' a _ = find ((==) (pemName a) . PEM.pemName) l
