-- |
-- Description : A Magic Wormhole library that supports file and directory transfer.
--
-- Magic Wormhole is a technology for getting things from one computer to another, safely.
--
-- To use it, you must use the MagicWormhole library to first establish an encrypted connection:
--
--   1. Start a 'Rendezvous.Session' with the Rendezvous server, to allow peers to find each other ('Rendezvous.runClient')
--   2. Negotiate a shared 'Messages.Nameplate' so peers can find each other on the server ('Rendezvous.allocate', 'Rendezvous.list')
--   3. Use the shared 'Messages.Nameplate' to 'Rendezvous.open' a shared 'Messages.Mailbox'
--   4. Use a secret password shared between peers to establish an encrypted connection ('Peer.withEncryptedConnection')
--
-- Once you've done this, you can communicate with your peer via 'Transit.send' and 'Transit.receive'.
-- Once can send and receive either Text messages or Files.
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
