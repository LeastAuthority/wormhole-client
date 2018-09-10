module Transit.Internal.Conf
  ( Options(..)
  , Command(..)
  )
where

import Protolude

import qualified MagicWormhole

import Transit.Internal.Network (RelayEndpoint)
import Transit.Internal.FileTransfer (MessageType)

data Options
  = Options
  { cmd :: Command
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  , transitUrl :: RelayEndpoint
  } deriving (Eq, Show)

data Command
  = Send MessageType
  | Receive (Maybe Text)
  deriving (Eq, Show)
