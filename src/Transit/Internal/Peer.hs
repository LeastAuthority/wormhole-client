{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.Peer
  ( makeSenderHandshake
  , makeReceiverHandshake
  , makeSenderRecordKey
  , makeReceiverRecordKey
  , makeRelayHandshake
  , senderTransitExchange
  , senderFileOfferExchange
  , sendOffer
  , receiveOffer
  , sendMessageAck
  , receiveMessageAck
  , senderHandshakeExchange
  , receiverHandshakeExchange
  , sendTransitMsg
  , decodeTransitMsg
  , sendGoodAckMessage
  , receiveAckMessage
  , receiveWormholeMessage
  , sendWormholeMessage
  , generateTransitSide
  )
where

import Protolude

import qualified Control.Exception as E
import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

import Data.Aeson (encode, eitherDecode)
import Data.Binary.Get (getWord32be, runGet)
import Data.ByteString.Builder(toLazyByteString, word32BE)
import Data.Hex (hex)
import Data.Text (toLower)
import System.Posix.Types (FileOffset)
import System.PosixCompat.Files (getFileStatus, fileSize)
import System.FilePath (takeFileName)
import Network.Socket (PortNumber)
import Crypto.Random (MonadRandom(..))
import Data.ByteArray.Encoding (convertToBase, Base(Base16))

import Transit.Internal.Messages
  ( TransitMsg(..)
  , TransitAck(..)
  , Ack( FileAck, MessageAck )
  , Ability(..)
  , AbilityV1(..)
  , ConnectionHint)
import Transit.Internal.Network
  ( TCPEndpoint(..)
  , buildDirectHints
  , buildRelayHints
  , sendBuffer
  , recvBuffer
  , CommunicationError(..))
import Transit.Internal.Crypto
  ( encrypt
  , decrypt
  , deriveKeyFromPurpose
  , Purpose(..)
  , PlainText(..)
  , CipherText(..))

import qualified MagicWormhole

makeSenderHandshake :: SecretBox.Key -> ByteString
makeSenderHandshake key =
  (toS @Text @ByteString "transit sender ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose SenderHandshake key
    hexid = toS (toLower (toS @ByteString @Text (hex subkey)))

makeReceiverHandshake :: SecretBox.Key -> ByteString
makeReceiverHandshake key =
  (toS @Text @ByteString "transit receiver ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose ReceiverHandshake key
    hexid = toS (toLower (toS @ByteString @Text (hex subkey)))

-- | create relay handshake bytestring
-- "please relay HEXHEX for side XXXXX\n"
makeRelayHandshake :: SecretBox.Key -> MagicWormhole.Side -> ByteString
makeRelayHandshake key (MagicWormhole.Side side) =
  (toS @Text @ByteString "please relay ") <> token <> (toS @Text @ByteString " for side ") <> sideBytes <> "\n"
  where
    subkey = deriveKeyFromPurpose RelayHandshake key
    token = toS (toLower (toS @ByteString @Text (hex subkey)))
    sideBytes = toS @Text @ByteString side

makeSenderRecordKey :: SecretBox.Key -> Maybe SecretBox.Key
makeSenderRecordKey key =
  Saltine.decode (deriveKeyFromPurpose SenderRecord key)

makeReceiverRecordKey :: SecretBox.Key -> Maybe SecretBox.Key
makeReceiverRecordKey key =
  Saltine.decode (deriveKeyFromPurpose ReceiverRecord key)

-- |'transitExchange' exchanges transit message with the peer.
-- Sender sends a transit message with its abilities and hints.
-- Receiver sends either another Transit message or an Error message.
senderTransitExchange :: MagicWormhole.EncryptedConnection -> PortNumber -> IO (Either Text TransitMsg)
senderTransitExchange conn portnum = do
  let abilities' = [Ability DirectTcpV1, Ability RelayV1]
      relayHints = buildRelayHints
  directHints <- buildDirectHints portnum
  (_, rxMsg) <- concurrently (sendTransitMsg conn abilities' (directHints <> relayHints)) receiveTransitMsg
  case eitherDecode (toS rxMsg) of
    Right t@(Transit _ _) -> return (Right t)
    Left s -> return (Left (toS s))
    Right (Error errstr) -> return (Left errstr)
    Right (Answer _) -> return (Left "Answer message from the peer is unexpected")
  where
    receiveTransitMsg = do
      -- receive the transit from the receiving side
      responseMsg <- receiveWormholeMessage conn
      return responseMsg

sendTransitMsg :: MagicWormhole.EncryptedConnection -> [Ability] -> [ConnectionHint] -> IO ()
sendTransitMsg conn abilities' hints' = do
  -- create transit message
  let txTransitMsg = Transit abilities' hints'
  let encodedTransitMsg = toS (encode txTransitMsg)
  -- send the transit message (dictionary with key as "transit" and value as abilities)
  MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)

decodeTransitMsg :: ByteString -> Either CommunicationError TransitMsg
decodeTransitMsg received =
  case eitherDecode (toS received) of
    Right transitMsg -> Right transitMsg
    Left err -> Left $ TransitError (toS err)

sendOffer :: MagicWormhole.EncryptedConnection -> MagicWormhole.Offer -> IO ()
sendOffer conn offer =
  MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode offer)))

-- | receive a message over wormhole and try to decode it as an offer message.
-- If it is not an offer message, pass the raw bytestring as a Left value.
receiveOffer :: MagicWormhole.EncryptedConnection -> IO (Either ByteString MagicWormhole.Offer)
receiveOffer conn = do
  received <- receiveWormholeMessage conn
  case eitherDecode (toS received) of
    Right msg@(MagicWormhole.Message _) -> return $ Right msg
    Right file@(MagicWormhole.File _ _) -> return $ Right file
    Right dir@(MagicWormhole.Directory _ _ _ _ _) -> return $ Right dir
    Left _ -> return $ Left received

receiveMessageAck :: MagicWormhole.EncryptedConnection -> IO ()
receiveMessageAck conn = do
  rxTransitMsg <- receiveWormholeMessage conn
  case eitherDecode (toS rxTransitMsg) of
    Left s -> throwIO (TransitError (show s))
    Right (Answer (MessageAck msg')) | msg' == "ok" -> return ()
                                     | otherwise -> throwIO (TransitError "Message ack failed")
    Right s -> throwIO (TransitError (show s))

sendMessageAck :: MagicWormhole.EncryptedConnection -> Text -> IO ()
sendMessageAck conn msg = do
  let ackMessage = Answer (MessageAck msg)
  MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode ackMessage)))

senderFileOfferExchange :: MagicWormhole.EncryptedConnection -> FilePath -> IO (Either Text ())
senderFileOfferExchange conn path = do
  (_,rx) <- concurrently sendFileOffer receiveResponse
  -- receive file ack message {"answer": {"file_ack": "ok"}}
  case eitherDecode (toS rx) of
    Left s -> return $ Left (toS s)
    Right (Error errstr) -> return $ Left (toS errstr)
    Right (Answer (FileAck msg)) | msg == "ok" -> return (Right ())
                                 | otherwise -> return $ Left "Did not get file ack. Exiting"
    Right (Answer (MessageAck _)) -> return $ Left "expected file ack, got message ack instead"
    Right (Transit _ _) -> return $ Left "unexpected transit message"
  where
    sendFileOffer :: IO ()
    sendFileOffer = do
      size <- getFileSize path
      let fileOffer = MagicWormhole.File (toS (takeFileName path)) size
      sendOffer conn fileOffer
    receiveResponse :: IO ByteString
    receiveResponse = do
      rxFileOffer <- receiveWormholeMessage conn
      return rxFileOffer
    getFileSize :: FilePath -> IO FileOffset
    getFileSize file = fileSize <$> getFileStatus file

receiveWormholeMessage :: MagicWormhole.EncryptedConnection -> IO ByteString
receiveWormholeMessage conn = do
  MagicWormhole.PlainText msg <- atomically $ MagicWormhole.receiveMessage conn
  return msg

sendWormholeMessage :: MagicWormhole.EncryptedConnection -> BL.ByteString -> IO ()
sendWormholeMessage conn msg =
  MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS msg))

data InvalidHandshake = InvalidHandshake
                      | InvalidRelayHandshake
  deriving (Show, Eq)

instance E.Exception InvalidHandshake where

relayHandshakeExchange :: TCPEndpoint -> SecretBox.Key -> MagicWormhole.Side -> IO ()
relayHandshakeExchange ep key side = do
  r <- sendRelayHandshake >> receiveAck
  if r == "ok\n"
    then return ()
    else throwIO InvalidRelayHandshake
  where
    sendRelayHandshake = sendBuffer ep sHandshakeMsg
    sHandshakeMsg = makeRelayHandshake key side
    receiveAck = recvByteString (BS.length rHandshakeMsg)
    rHandshakeMsg = "ok\n"
    recvByteString n = recvBuffer ep n

senderHandshakeExchange :: TCPEndpoint -> SecretBox.Key -> MagicWormhole.Side -> IO ()
senderHandshakeExchange ep key side = do
  when (conntype ep == Just RelayV1) $ do
    relayHandshakeExchange ep key side
  (_, r) <- concurrently sendHandshake rxHandshake
  if r == rHandshakeMsg
    then sendGo >> return ()
    else sendNeverMind >> throwIO InvalidHandshake
  where
    sendHandshake = sendBuffer ep sHandshakeMsg
    rxHandshake = recvByteString (BS.length rHandshakeMsg)
    sendGo = sendBuffer ep (toS @Text @ByteString "go\n")
    sendNeverMind = sendBuffer ep (toS @Text @ByteString "nevermind\n")
    sHandshakeMsg = makeSenderHandshake key
    rHandshakeMsg = makeReceiverHandshake key
    recvByteString n = recvBuffer ep n

receiverHandshakeExchange :: TCPEndpoint -> SecretBox.Key -> MagicWormhole.Side -> IO ()
receiverHandshakeExchange ep key side = do
  when (conntype ep == Just RelayV1) $ do
    relayHandshakeExchange ep key side
  (_, r') <- concurrently sendHandshake rxHandshake
  r'' <- recvByteString (BS.length "go\n")
  if (r' <> r'') == sHandshakeMsg <> "go\n"
    then return ()
    else throwIO InvalidHandshake
    where
        sendHandshake = sendBuffer ep rHandshakeMsg
        rxHandshake = recvByteString (BS.length sHandshakeMsg)
        sHandshakeMsg = makeSenderHandshake key
        rHandshakeMsg = makeReceiverHandshake key
        recvByteString n = recvBuffer ep n
    
receiveAckMessage :: TCPEndpoint -> SecretBox.Key -> IO (Either Text Text)
receiveAckMessage ep key = do
  ackBytes <- BL.fromStrict <$> receiveRecord ep key
  case eitherDecode ackBytes of
    Right (TransitAck msg checksum) | msg == "ok" -> return (Right checksum)
                                    | otherwise -> return (Left "transit ack failure")
    Left s -> return (Left $ toS ("transit ack failure: " <> s))

sendGoodAckMessage :: TCPEndpoint -> SecretBox.Key -> ByteString -> IO ()
sendGoodAckMessage ep key sha256Sum = do
  let transitAckMsg = TransitAck "ok" (toS @ByteString @Text sha256Sum)
      maybeEncMsg = encrypt key Saltine.zero (PlainText (BL.toStrict (encode transitAckMsg)))
    in
    case maybeEncMsg of
      Right (CipherText encMsg) -> sendRecord ep encMsg >> return ()
      Left e -> throwIO e

sendRecord :: TCPEndpoint -> ByteString -> IO Int
sendRecord ep record = do
  -- send size of the encrypted payload as 4 bytes, then send record
  -- format sz as a fixed 4 byte bytestring
  let payloadSize = toLazyByteString (word32BE (fromIntegral (BS.length record)))
  _ <- sendBuffer ep (toS payloadSize) `catch` \e -> throwIO (e :: E.SomeException)
  sendBuffer ep record `catch` \e -> throwIO (e :: E.SomeException)

receiveRecord :: TCPEndpoint -> SecretBox.Key -> IO ByteString
receiveRecord ep key = do
  -- read 4 bytes that consists of length
  -- read as much bytes specified by the length. That would be encrypted record
  -- decrypt the record
    lenBytes <- recvBuffer ep 4
    let len = runGet getWord32be (BL.fromStrict lenBytes)
    encRecord <- recvBuffer ep (fromIntegral len)
    case decrypt key (CipherText encRecord) of
      Left e -> throwIO e
      Right (PlainText pt, _) -> return pt

generateTransitSide :: MonadRandom m => m MagicWormhole.Side
generateTransitSide = do
  randomBytes <- getRandomBytes 8
  pure . MagicWormhole.Side . toS @ByteString . convertToBase Base16 $ (randomBytes :: ByteString)

