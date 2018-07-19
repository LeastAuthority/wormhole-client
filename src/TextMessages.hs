module TextMessages
  ( sendText
  , receiveText
  )
where

import Protolude

import qualified Crypto.Spake2 as Spake2
import qualified Data.Text as Text
import qualified Data.Aeson as Aeson

import qualified MagicWormhole

-- | A password used to exchange with a Magic Wormhole peer.
--
-- XXX: Just picking ByteString because that's the least amount of work. Need
-- to look up exact type of password in the magic-wormhole docs.
type Password = ByteString

-- | Send a text message to a Magic Wormhole peer.
sendText :: MagicWormhole.Session -> Password -> (Text -> IO ()) -> Text -> IO ()
sendText session password printHelpFn message = do
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox
  let (MagicWormhole.Nameplate n) = nameplate
  printHelpFn $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        let offer = MagicWormhole.Message message
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (Aeson.encode offer))))

-- | Receive a text message from a Magic Wormhole peer.
receiveText :: MagicWormhole.Session -> Text -> IO Text
receiveText session code = do
  let codeSplit = Text.split (=='-') code
  let (Just nameplate) = headMay codeSplit
  mailbox <- MagicWormhole.claim session (MagicWormhole.Nameplate nameplate)
  peer <- MagicWormhole.open session mailbox
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS (Text.strip code)))
    (\conn -> do
        MagicWormhole.PlainText received <- atomically $ MagicWormhole.receiveMessage conn
        case Aeson.eitherDecode (toS received) of
          Left err -> panic $ "Could not decode message: " <> show err
          Right (MagicWormhole.Message message) -> pure message
          Right (MagicWormhole.File _ _) -> panic "Unexpected message type"
    )
