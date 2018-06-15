module FileTransfer
  (
    sendFile
--  , receiveFile
  )
where

import Protolude

import qualified Data.Text.IO as TIO
import qualified Crypto.Spake2 as Spake2
import Data.Aeson
  ( FromJSON(..)
  , ToJSON(..)
  , (.:)
  , (.=)
  , object
  , withObject
  , encode
  , Value(String)
  )

import qualified MagicWormhole

import Helper

data ConnectionType
  = DirectTCP
  | RelayTCP
  deriving (Eq, Show)

newtype Ability
  = Ability [ConnectionType]
    deriving (Eq, Show)

newtype Hint
  = Hint [ConnectionHint]
  deriving (Eq, Show)

data ConnectionHint
  = Direct { name :: Text
           , priority :: Double
           , hostname :: Text
           , port :: Integer }
    -- TODO: or Relay Hint
  deriving (Eq, Show)

data Transit
  = Transit { abilities :: [ConnectionType]
            , hints :: [ConnectionHint] }
  deriving (Eq, Show)

instance ToJSON ConnectionType where
  toJSON DirectTCP = object [ "type" .= String "direct-tcp-v1" ]
  toJSON RelayTCP  = object [ "type" .= String "relay-v1" ]

instance ToJSON ConnectionHint where
  toJSON (Direct name' prio hostname' port') = object [ "type" .= name'
                                                      , "priority" .= prio
                                                      , "hostname" .= hostname'
                                                      , "port" .= port' ]
  -- TODO: add Relay and the encoding for it.

instance FromJSON ConnectionHint where
  parseJSON = withObject "Connection Hint" $ \o -> Direct
    <$> o .: "name"
    <*> o .: "priority"
    <*> o .: "hostname"
    <*> o .: "port"
  -- TODO: 'asum' of Relay Hint parsing as well.

instance ToJSON Transit where
  toJSON (Transit as hs) = object [ "transit" .= object [ "abilities-v1" .= toJSON as
                                                        , "hints-v1" .= toJSON hs ] ]
  
type Password = ByteString

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

sendFile :: MagicWormhole.Session -> Password -> FilePath -> IO () -- Response
sendFile session password filepath = do
--   -- steps
--   -- * first establish a wormhole session with the receiver and
--   --   then talk the filetransfer protocol over it as follows.
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printSendHelpText $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        -- create abilities
        -- send transit message via wormhole as an ordinary message
        let abilities' = [DirectTCP]
        let hints' = [Direct "direct-hint-v1" 0.0 "127.0.0.1" 4848]
        let transitMsg = Transit abilities' hints'
        let encodedTransitMsg = toS (encode transitMsg)
        -- send the transit message (dictionary with key as "transit" and value as abilities)
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)

        -- receive the transit from the receiving side
        MagicWormhole.PlainText answerMsg <- atomically $ MagicWormhole.receiveMessage conn
        TIO.putStrLn (toS answerMsg)

        -- send file offer message
        let fileOffer = MagicWormhole.File (toS filepath) 10
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode fileOffer)))

        -- receive file ack message {"answer": {"file_ack": "ok"}}
        -- TODO: verify that file_ack is "ok"
        MagicWormhole.PlainText rxFileOffer <- atomically $ MagicWormhole.receiveMessage conn
        TIO.putStrLn (toS rxFileOffer)

        -- we are now ready to prepare for the TCP communication
        -- TODO derive a transit key
        return ()
    )

--   -- * establish the tcp connection with the peer/relay
--   -- * send handshake message:
--   --     sender -> receiver: transit sender TXID_HEX ready\n\n
--   --     receiver -> sender: transit receiver RXID_HEX ready\n\n
--   -- * if sender is satisfied with the handshake, it sends
--   --     sender -> receiver: go\n
--   -- * TXID_HEX above is the HKDF(transit_key, 32, CTXinfo=b'transit_sender') for sender
--   --    and HKDF(transit_key, 32, CTXinfo=b'transit_receiver')
--   -- * TODO: relay handshake
--   -- * create record_keys (send_record_key and receive_record_key (secretboxes)
--   -- * send the file (40 byte chunks) over a direct connection to either the relay or peer.
--   -- * receiver, once it successfully received the file, sends "{ 'ack' : 'ok', 'sha256': HEXHEX }
  
  
-- receiveFile :: Session -> Passcode -> IO Status
