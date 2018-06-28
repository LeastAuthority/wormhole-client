{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
module FileTransfer
  (
--    sendFile
  -- for tests
    Ability(..)
  , Hint(..)
  , ConnectionHint(..)
  , Transit(..)
  , abilities'
  )
where

import Protolude
import GHC.Generics

import qualified Data.Text.IO as TIO
import qualified Crypto.Spake2 as Spake2
import Data.Aeson
  ( FromJSON(..)
  , ToJSON(..)
  , genericToJSON
  , genericToEncoding
  , genericParseJSON
  , defaultOptions
  , defaultTaggedObject
  , fieldLabelModifier
  , constructorTagModifier
  , allNullaryToStringTag
  , sumEncoding
  , SumEncoding(..)
  , camelTo2
  , (.:)
  , (.=)
  , object
  , withObject
  , withScientific
  , withArray
  , encode
  , decode
  , eitherDecode
  , Value(String, Array)
  )
import Data.Aeson.Types
  ( Parser
  , parseMaybe
  )

import qualified Control.Exception as E
import Network.Socket
  ( addrSocketType
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
import qualified Data.Vector as V
import qualified Data.HashMap.Strict as HM

import qualified MagicWormhole

import Helper

data Ability
  = DirectTcpV1
  | RelayV1
  deriving (Eq, Show, Generic)

instance ToJSON Ability where
  toJSON = genericToJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

instance FromJSON Ability where
  parseJSON = genericParseJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

data Hint = Hint { ctype :: Ability
                 , priority :: Double
                 , hostname :: Text
                 , port :: Word16 }
          deriving (Eq, Show, Generic)

instance ToJSON Hint where
  toJSON = genericToJSON
    defaultOptions { fieldLabelModifier =
                       \name -> case name of
                                  "ctype" -> "type"
                                  _ -> name }

instance FromJSON Hint where
  parseJSON = genericParseJSON
    defaultOptions { fieldLabelModifier =
                       \name -> case name of
                                  "ctype" -> "type"
                                  _ -> name }

data ConnectionHint
  = Direct Hint
  | Tor Hint
  | Relay { rtype :: Ability
          , hints :: [Hint] }
  deriving (Eq, Show, Generic)

instance ToJSON ConnectionHint where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier =
                       \name -> case name of
                                  "rtype" -> "type"
                                  _ -> name }
instance FromJSON ConnectionHint where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier =
                       \name -> case name of
                                  "rtype" -> "type"
                                  _ -> name }


data Transit
  = Transit { abilitiesV1 :: [Ability]
            , hintsV1 :: [ConnectionHint] }
  deriving (Eq, Show)

instance ToJSON Transit where
  toJSON (Transit as hs) = object [ "transit" .= object [ "abilities-v1" .= map (\x -> object [ "type" .= toJSON x ]) as
                                                        , "hints-v1" .= toJSON hs ] ]

abilities' :: Value -> Parser [Ability]
abilities' = withArray "array of key objects" $ \arr ->
               mapM (withObject "obj" $ \o -> o .: "type") (V.toList arr)

instance FromJSON Transit where
  parseJSON = withObject "Transit" $ \o ->
    o .: "transit" >>=
    (\x -> do
        av <- x .: "abilities-v1"
        let vs = abilities' av
        Transit <$> vs <*> x .: "hints-v1")

{-|

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
|-}
