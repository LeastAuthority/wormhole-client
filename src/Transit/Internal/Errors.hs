module Transit.Internal.Errors
  ( liftEitherCommError
    -- * Error
  , Error(..)
  , N.CommunicationError(..)
  , P.InvalidHandshake
  , C.CryptoError
  )
where

import Protolude

import qualified Control.Exception as E

import qualified Transit.Internal.Network as N
import qualified Transit.Internal.Crypto as C
import qualified Transit.Internal.Peer as P

data Error = CipherError C.CryptoError
           | GeneralError N.CommunicationError
           | HandshakeError P.InvalidHandshake
           deriving (Show)

instance E.Exception Error

liftEitherCommError :: Either N.CommunicationError a -> Either Error a
liftEitherCommError = first GeneralError
