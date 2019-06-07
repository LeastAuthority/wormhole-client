-- | Description: Application Configuration
module Transit.Internal.Conf
  ( Cmdline(..)
  , Command(..)
  , Options(..)
  )
where

import Protolude

import qualified MagicWormhole

import Transit.Internal.Network (RelayEndpoint)
import Transit.Internal.FileTransfer (MessageType)

-- | Application Configuration options
data Cmdline
  = Cmdline
  { options :: Options
    -- ^ command line arguments
  , cmd :: Command
    -- ^ send or receive
  } deriving (Eq, Show)

data Options
  = Options
  { relayEndpoint :: MagicWormhole.WebSocketEndpoint
    -- ^ Rendezvous server websocket endpoint URL
  , transitUrl :: RelayEndpoint
    -- ^ Transit Relay URL
  , appId :: MagicWormhole.AppID
    -- ^ Application ID string
  , useTor :: Bool
    -- ^ Whether to use Tor for all network communication
  } deriving (Eq, Show)

-- | Commands
data Command
  = Send MessageType
  -- ^ Send a file, directory or a text message
  | Receive (Maybe Text)
  -- ^ Receive a file, directory or a text message
  deriving (Eq, Show)
