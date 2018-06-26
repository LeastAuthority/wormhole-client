{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
module FileTransfer
  (
    sendFile
--  , receiveFile
  -- for tests
  , ConnectionType(..)
  , ConnectionHint(..)
  , PortNum(..)
  , Transit(..)
  )
where

import Protolude
-- import GHC.Generics

import qualified Data.Text.IO as TIO
import qualified Crypto.Spake2 as Spake2
import Data.Aeson
  ( FromJSON(..)
  , ToJSON(..)
  , (.:)
  , (.=)
  , object
  , withObject
  , withScientific
  , encode
  , eitherDecode
  , Value(String)
  )

import qualified Control.Exception as E
import Network.Socket
  ( PortNumber
  , addrSocketType
  , addrFlags
  , socketPort
  , addrAddress
  , addrProtocol
  , addrFamily
  , getAddrInfo
  , SocketType ( Stream )
  , close
  , socket
  , bind
  , defaultHints
  , defaultPort
  , setSocketOption
  , SocketOption( ReuseAddr )
  , AddrInfoFlag ( AI_NUMERICSERV )
  )
import Data.Scientific
  ( coefficient
  )
import System.Posix.Files
  ( getFileStatus
  , fileSize
  )
import System.Posix.Types
  ( FileOffset
  )

import qualified MagicWormhole

import Helper

data ConnectionType
  = DirectTCP
  | RelayTCP
  deriving (Eq, Show)

newtype PortNum = PortNum { getPortNumber :: PortNumber }
  deriving (Eq, Show, Integral, Real, Enum, Num, Ord)

data ConnectionHint
  = Direct { name :: Text
           , priority :: Double
           , hostname :: Text
           , port :: PortNum }
  | Relay { name :: Text
          , priority :: Double
          , hostname :: Text
          , port :: PortNum }
  deriving (Eq, Show)

data Transit
  = Transit { abilities :: [ConnectionType]
            , hints :: [ConnectionHint] }
  deriving (Eq, Show)

instance ToJSON ConnectionType where
  toJSON DirectTCP = object [ "type" .= (String "direct-tcp-v1") ]
  toJSON RelayTCP  = object [ "type" .= (String "relay-v1") ]

instance FromJSON ConnectionType where
  parseJSON = withObject "ConnectionType" $ \o -> do
    kind <- o .: "type"
    case (kind :: Text) of
      "direct-tcp-v1" -> return DirectTCP
      "relay-v1" -> return RelayTCP

instance ToJSON PortNum where
  toJSON n = toJSON $ (toInteger n)

instance FromJSON PortNum where
  parseJSON = withScientific "PortNumber" (return . fromInteger . coefficient)

instance ToJSON ConnectionHint where
  toJSON (Direct name' prio hostname' port') = object [ "type" .= name'
                                                      , "priority" .= prio
                                                      , "hostname" .= hostname'
                                                      , "port" .= port' ]
  toJSON (Relay name' prio hostname' port') = object [ "type" .= name'
                                                     , "priority" .= prio
                                                     , "hostname" .= hostname'
                                                     , "port" .= port' ]

instance FromJSON ConnectionHint where
  parseJSON = withObject "Connection Hint" $ \o -> asum [
    Direct <$> o .: "type" <*> o .: "priority" <*> o .: "hostname" <*> o .: "port",
    Relay <$> o .: "type" <*> o .: "priority" <*> o .: "hostname" <*> o .: "port" ]

instance ToJSON Transit where
  toJSON (Transit as hs) = object [ "transit" .= object [ "abilities-v1" .= toJSON as
                                                        , "hints-v1" .= toJSON hs ] ]

instance FromJSON Transit where
  parseJSON = withObject "Transit" $ \o ->
    o .: "transit" >>= (\x -> Transit <$> x .: "abilities-v1" <*> x .: "hints-v1")
  
type Password = ByteString

allocateTcpPort :: IO PortNumber
allocateTcpPort = E.bracket setup close socketPort
  where setup = do
          let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
          addr:_ <- getAddrInfo (Just hints') (Just "127.0.0.1") (Just (show defaultPort))
          sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
          _ <- setSocketOption sock ReuseAddr 1
          _ <- bind sock (addrAddress addr)
          return sock

getFileSize :: FilePath -> IO FileOffset
getFileSize file = fileSize <$> getFileStatus file

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
        let abilities' = [DirectTCP]
        port' <- allocateTcpPort
        let hints' = [Direct "direct-hint-v1" 0.0 "127.0.0.1" (PortNum port')]
        -- create transit message
        let transitMsg = Transit abilities' hints'
        let encodedTransitMsg = toS (encode transitMsg)
        -- send the transit message (dictionary with key as "transit" and value as abilities)
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)

        -- receive the transit from the receiving side
        MagicWormhole.PlainText answerMsg <- atomically $ MagicWormhole.receiveMessage conn
        TIO.putStrLn (toS answerMsg)

        -- TODO: parse peer's transit message
        let eitherTransitFromPeer = eitherDecode (toS answerMsg)
        case eitherTransitFromPeer of
          Left s -> TIO.putStrLn ("unable to decode transit message from peer: " <> toS s)
          Right transitMsgFromPeer -> do
            TIO.putStrLn transitMsgFromPeer

            -- send file offer message
            fileSize <- getFileSize filepath
            let fileOffer = MagicWormhole.File (toS filepath) fileSize
            MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode fileOffer)))

            -- receive file ack message {"answer": {"file_ack": "ok"}}
            -- TODO: verify that file_ack is "ok"
            MagicWormhole.PlainText rxFileOffer <- atomically $ MagicWormhole.receiveMessage conn
            TIO.putStrLn (toS rxFileOffer)

            -- TODO: parse offer message from the peer

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
