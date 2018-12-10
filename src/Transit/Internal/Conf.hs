module Transit.Internal.Conf
  ( Options(..)
  , Command(..)
  )
where

import Protolude

import qualified MagicWormhole

import Transit.Internal.Network (RelayEndpoint)
import Transit.Internal.FileTransfer (MessageType)

-- | Application Configuration options
data Options
  = Options
  { cmd :: Command
  -- ^ send or receive
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  -- ^ Rendezvous server websocket endpoint URL
  , transitUrl :: RelayEndpoint
  -- ^ Transit Relay URL
  } deriving (Eq, Show)

-- | Commands
data Command
  = Send MessageType
  -- ^ Send a file, directory or a text message
  | Receive (Maybe Text)
  -- ^ Receive a file, directory or a text message
  deriving (Eq, Show)
