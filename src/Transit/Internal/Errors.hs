-- | Description: Module for representing Error types
module Transit.Internal.Errors
  ( -- * Error
    Error(..)
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

-- | An Error type for the Magic Wormhole Transit Module
data Error = CipherError C.CryptoError
           | NetworkError N.CommunicationError
           | HandshakeError P.InvalidHandshake
           deriving (Show)

instance E.Exception Error
