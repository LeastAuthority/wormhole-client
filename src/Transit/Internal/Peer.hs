{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.Peer
  ( makeSenderHandshake
  , makeReceiverHandshake
  , makeSenderRecordKey
  , makeReceiverRecordKey
  , makeSenderRelayHandshake
  , transitExchange
  , senderOfferExchange
  , senderHandshakeExchange
  , receiverHandshakeExchange
  , sendTransitMsg
  , sendGoodAckMessage
  , receiveAckMessage
  , receiveWormholeMessage
  , sendWormholeMessage
  )
where

import Protolude

import qualified Control.Exception as E
import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import Data.Aeson (encode, eitherDecode)
import Data.Binary.Get (getWord32be, runGet)
import qualified Data.ByteString as BS
import Data.ByteString.Builder(toLazyByteString, word32BE)
import qualified Data.ByteString.Lazy as BL
import Data.Hex (hex)
import Data.Text (toLower)
import System.Posix.Types (FileOffset)
import System.PosixCompat.Files (getFileStatus, fileSize)
import System.FilePath (takeFileName)
import Network.Socket (PortNumber)

import Transit.Internal.Messages
  ( TransitMsg(..)
  , TransitAck(..)
  , Ack( FileAck, MsgAck )
  , Ability(..)
  , AbilityV1(..)
  , ConnectionHint)
import Transit.Internal.Network
  ( TCPEndpoint(..)
  , PortNumber
  , buildDirectHints
  , closeConnection
  , sendBuffer
  , recvBuffer
  , CommunicationError(..))
import Transit.Internal.Crypto
  ( encrypt,
    decrypt,
    deriveKeyFromPurpose,
    Purpose(..))

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

-- | create sender's relay handshake bytestring
-- "please relay HEXHEX for side XXXXX\n"
makeSenderRelayHandshake :: SecretBox.Key -> MagicWormhole.Side -> ByteString
makeSenderRelayHandshake key (MagicWormhole.Side side) =
  (toS @Text @ByteString "please relay ") <> token <> (toS @Text @ByteString " for side ") <> sideBytes <> "\n"
  where
    subkey = deriveKeyFromPurpose SenderRelayHandshake key
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
transitExchange :: MagicWormhole.EncryptedConnection -> PortNumber -> IO (Either Text TransitMsg)
transitExchange conn portnum = do
  let abilities' = [Ability DirectTcpV1]
  hints' <- buildDirectHints portnum
  (_, rxMsg) <- concurrently (sendTransitMsg conn abilities' hints') receiveTransitMsg
  case eitherDecode (toS rxMsg) of
    Right t@(Transit _ _) -> return (Right t)
    Left s -> return (Left (toS s))
    Right (Error errstr) -> return (Left errstr)
    Right (Answer _) -> return (Left "Answer message from the peer is unexpected")
  where
    receiveTransitMsg = do
      -- receive the transit from the receiving side
      MagicWormhole.PlainText responseMsg <- atomically $ MagicWormhole.receiveMessage conn
      return responseMsg

sendTransitMsg :: MagicWormhole.EncryptedConnection -> [Ability] -> [ConnectionHint] -> IO ()
sendTransitMsg conn abilities' hints' = do
  -- create transit message
  let txTransitMsg = Transit abilities' hints'
  let encodedTransitMsg = toS (encode txTransitMsg)

  -- send the transit message (dictionary with key as "transit" and value as abilities)
  MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)


senderOfferExchange :: MagicWormhole.EncryptedConnection -> FilePath -> IO (Either Text ())
senderOfferExchange conn path = do
  (_,rx) <- concurrently sendOffer receiveResponse
  -- receive file ack message {"answer": {"file_ack": "ok"}}
  case eitherDecode (toS rx) of
    Left s -> return $ Left (toS s)
    Right (Error errstr) -> return $ Left (toS errstr)
    Right (Answer (FileAck msg)) | msg == "ok" -> return (Right ())
                                 | otherwise -> return $ Left "Did not get file ack. Exiting"
    Right (Answer (MessageAck _)) -> return $ Left "expected file ack, got message ack instead"
    Right (Transit _ _) -> return $ Left "unexpected transit message"
  where
    sendOffer :: IO ()
    sendOffer = do
      size <- getFileSize path
      let fileOffer = MagicWormhole.File (toS (takeFileName path)) size
      MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode fileOffer)))
    receiveResponse :: IO ByteString
    receiveResponse = do
      MagicWormhole.PlainText rxFileOffer <- atomically $ MagicWormhole.receiveMessage conn
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
  deriving (Show, Eq)

instance E.Exception InvalidHandshake where

senderHandshakeExchange :: TCPEndpoint -> SecretBox.Key -> IO ()
senderHandshakeExchange ep key = do
  (_, r) <- concurrently sendHandshake rxHandshake
  if r == rHandshakeMsg
      then sendGo >> return ()
      else sendNeverMind >> closeConnection ep
  where
    sendHandshake = sendBuffer ep sHandshakeMsg
    rxHandshake = recvByteString (BS.length rHandshakeMsg)
    sendGo = sendBuffer ep (toS @Text @ByteString "go\n")
    sendNeverMind = sendBuffer ep (toS @Text @ByteString "nevermind\n")
    sHandshakeMsg = makeSenderHandshake key
    rHandshakeMsg = makeReceiverHandshake key
    recvByteString n = recvBuffer ep n

receiverHandshakeExchange :: TCPEndpoint -> SecretBox.Key -> IO ()
receiverHandshakeExchange ep key = do
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
      maybeEncMsg = encrypt key Saltine.zero (BL.toStrict (encode transitAckMsg))
    in
    case maybeEncMsg of
      Right encMsg -> sendRecord ep encMsg >> return ()
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
    case decrypt key encRecord of
      Left e -> throwIO e
      Right (pt, _) -> return pt

