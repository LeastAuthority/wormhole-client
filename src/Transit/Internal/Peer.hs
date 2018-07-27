{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.Peer
  ( makeSenderHandshake
  , makeReceiverHandshake
  , makeSenderRecordKey
  , makeReceiverRecordKey
  , transitExchange
  , senderOfferExchange
  , senderHandshakeExchange
  , receiverHandshakeExchange
  , sendTransitMsg
  , receiveRecords
  , sendGoodAckMessage
  , receiveAckMessage
  , receiveWormholeMessage
  , sendWormholeMessage
  , sha256sum
  , encryptC
  , sha256PassThroughC
  )
where

import Protolude

import qualified Control.Exception as E
import Crypto.Hash (SHA256(..))
import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import Crypto.Saltine.Internal.ByteSizes (boxNonce)
import qualified Crypto.Saltine.Internal.ByteSizes as ByteSizes
import Data.Aeson (encode, eitherDecode)
import Data.Binary.Get (getWord32be, runGet)
import qualified Data.ByteString as BS
import Data.ByteString.Builder(toLazyByteString, word32BE)
import qualified Data.ByteString.Lazy as BL
import Data.Hex (hex)
import Data.Text (toLower)
import System.Posix.Types (FileOffset)
import System.PosixCompat.Files (getFileStatus, fileSize)
import qualified Conduit as C

import Transit.Internal.Messages
import Transit.Internal.Network

import qualified MagicWormhole

hkdf :: ByteString -> SecretBox.Key -> ByteString -> ByteString
hkdf salt key purpose =
  HKDF.expand (HKDF.extract salt (Saltine.encode key) :: HKDF.PRK SHA256) purpose keySize
  where
    keySize = ByteSizes.secretBoxKey

data Purpose
  = SenderHandshake
  | ReceiverHandshake
  | SenderRecord
  | ReceiverRecord
  deriving (Eq, Show)

deriveKeyFromPurpose :: Purpose -> SecretBox.Key -> ByteString
deriveKeyFromPurpose purpose key =
  hkdf salt key (purposeStr purpose)
  where
    salt = "" :: ByteString
    purposeStr :: Purpose -> ByteString
    purposeStr SenderHandshake = "transit_sender"
    purposeStr ReceiverHandshake = "transit_receiver"
    purposeStr SenderRecord = "transit_record_sender_key"
    purposeStr ReceiverRecord = "transit_record_receiver_key"

makeSenderHandshake :: SecretBox.Key -> ByteString
makeSenderHandshake key =
  (toS @Text @ByteString "transit sender ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose SenderHandshake key
    hexid = (toS (toLower (toS @ByteString @Text (hex subkey))))

makeReceiverHandshake :: SecretBox.Key -> ByteString
makeReceiverHandshake key =
  (toS @Text @ByteString "transit receiver ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose ReceiverHandshake key
    hexid = (toS (toLower (toS @ByteString @Text (hex subkey))))

makeSenderRecordKey :: SecretBox.Key -> SecretBox.Key
makeSenderRecordKey key =
  fromMaybe (panic "Could not encode to SecretBox key") $
  Saltine.decode (deriveKeyFromPurpose SenderRecord key)

makeReceiverRecordKey :: SecretBox.Key -> SecretBox.Key
makeReceiverRecordKey key =
  fromMaybe (panic "Could not encode to SecretBox key") $
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
    Right (Answer (MsgAck _)) -> return $ Left "expected file ack, got message ack instead"
    Right (Transit _ _) -> return $ Left "unexpected transit message"
  where
    sendOffer :: IO ()
    sendOffer = do
      size <- getFileSize path
      let fileOffer = MagicWormhole.File (toS path) size
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
  _ <- sendRecord ep (encrypt key Saltine.zero (BL.toStrict (encode transitAckMsg)))
  return ()

type PlainText = ByteString
type CipherText = ByteString

sendRecord :: TCPEndpoint -> ByteString -> IO Int
sendRecord ep record = do
  -- send size of the encrypted payload as 4 bytes, then send record
  -- format sz as a fixed 4 byte bytestring
  let payloadSize = toLazyByteString (word32BE (fromIntegral (BS.length record)))
  _ <- sendBuffer ep (toS payloadSize) `catch` \e -> throwIO (e :: E.SomeException)
  sendBuffer ep record `catch` \e -> throwIO (e :: E.SomeException)

encryptC :: Monad m => SecretBox.Key -> C.ConduitT ByteString ByteString m ()
encryptC key = go Saltine.zero
  where
    go nonce = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just chunk -> do
          let cipherText = encrypt key nonce chunk
              cipherTextSize = toLazyByteString (word32BE (fromIntegral (BS.length cipherText)))
          C.yield (toS cipherTextSize)
          C.yield cipherText
          go (Saltine.nudge nonce)

sha256PassThroughC :: (Monad m) => C.ConduitT ByteString ByteString m Text
sha256PassThroughC = go $! Hash.hashInitWith SHA256
  where
    go :: (Monad m) => Hash.Context SHA256 -> C.ConduitT ByteString ByteString m Text
    go ctx = do
      b <- C.await
      case b of
        Nothing -> return $! (show (Hash.hashFinalize ctx))
        Just bs -> do
          C.yield bs
          go $! Hash.hashUpdate ctx bs


sha256sum :: [ByteString] -> Hash.Digest Hash.SHA256
sha256sum = hashBlocks (Hash.hashInitWith Hash.SHA256)
  where
    hashBlocks :: Hash.Context Hash.SHA256 -> [ByteString] -> Hash.Digest Hash.SHA256
    hashBlocks ctx [] = Hash.hashFinalize ctx
    hashBlocks ctx (r:rs) = hashBlocks (Hash.hashUpdate ctx r) rs

-- | encrypt the given chunk with the given secretbox key and nonce.
-- Saltine's nonce seem represented as a big endian bytestring.
-- However, to interop with the wormhole python client, we need to
-- use and send nonce as a little endian bytestring.
encrypt :: SecretBox.Key -> SecretBox.Nonce -> PlainText -> CipherText
encrypt key nonce plaintext =
  let nonceLE = BS.reverse $ toS $ Saltine.encode nonce
      newNonce = fromMaybe (panic "nonce decode failed") $
                 Saltine.decode (toS nonceLE)
      ciphertext = toS $ SecretBox.secretbox key newNonce plaintext
  in
    nonceLE <> ciphertext

decrypt :: SecretBox.Key -> CipherText -> Either Text PlainText
decrypt key ciphertext =
  -- extract nonce from ciphertext.
  let (nonceBytes, ct) = BS.splitAt boxNonce ciphertext
      nonce = fromMaybe (panic "unable to decode nonce") $
              Saltine.decode nonceBytes
      maybePlainText = SecretBox.secretboxOpen key nonce ct
  in
    case maybePlainText of
      Just pt -> Right pt
      Nothing -> Left "decription error"

receiveRecord :: TCPEndpoint -> SecretBox.Key -> IO ByteString
receiveRecord ep key = do
  -- read 4 bytes that consists of length
  -- read as much bytes specified by the length. That would be encrypted record
  -- decrypt the record
  do
    lenBytes <- recvBuffer ep 4
    let len = runGet getWord32be (BL.fromStrict lenBytes)
    encRecord <- recvBuffer ep (fromIntegral len)
    case decrypt key encRecord of
      Left s -> panic s
      Right pt -> return pt

receiveRecords :: TCPEndpoint -> SecretBox.Key -> Int -> IO [ByteString]
receiveRecords ep key size = do
  go size
    where
      go :: Int -> IO [ByteString]
      go remainingSize | remainingSize <= 0 = return []
                       | otherwise = do
                           block <- receiveRecord ep key
                           blocks <- go (remainingSize - BS.length block)
                           return (block:blocks)

