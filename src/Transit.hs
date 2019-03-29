-- |
-- Description : A Magic Wormhole library that supports file and directory transfer.
--
-- Magic Wormhole is a technology for getting things from one computer to another, safely.
--
-- In order to use the library in an application, you need to create an "application ID"
-- which is a unique application specific ascii string, a random 5-byte bytestring called
-- "side" and a few application configuration options defined in 'Options' type in the
-- 'Conf' module which sets up the transit server url, relay server url and the mode (send
-- or receive).
--
-- Once the environment and the configurations are set, the 'app' can be run via 'App.runApp'.

-- The 'app' takes care of the following:
--
--   0. Prompt the user for a passcode (or can also be passed via command line) in the case of receiving or generate a passcode in the case of sending.
--   1. Start a 'Rendezvous.Session' with the Rendezvous server, to allow peers to find each other ('Rendezvous.runClient')
--   2. Negotiate a shared 'Messages.Nameplate' so peers can find each other on the server ('Rendezvous.allocate', 'Rendezvous.list')
--   3. Use the shared 'Messages.Nameplate' to 'Rendezvous.open' a shared 'Messages.Mailbox'
--   4. Use a secret password shared between peers to establish an encrypted connection ('Peer.withEncryptedConnection')
--   5. Establish a TCP connection directly if they are reachable on the same network or via a relay server and send the encrypted file or a directory over the connection.
--
-- The password is never sent over the wire.
-- Rather, it is used to negotiate a session key using SPAKE2,
-- and that key itself is used to derive many per-message keys,
-- so that each message is encrypted using NaCl SecretBox.
--
module Transit
  ( App.Env(..)
  , App.prepareAppEnv
  , App.app
  , App.runApp
  , App.send
  , App.receive
  , Conf.Options(..)
  , Conf.Command(..)
  , Errors.Error(..)
  , FileTransfer.MessageType(..)
  , MagicWormhole.parseWebSocketEndpoint
  , Network.parseTransitRelayUri
  )
where

import qualified Transit.Internal.FileTransfer as FileTransfer
import qualified Transit.Internal.Network as Network
import qualified Transit.Internal.Errors as Errors
import qualified Transit.Internal.Conf as Conf
import qualified Transit.Internal.App as App
import qualified MagicWormhole
