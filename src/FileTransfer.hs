{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module FileTransfer
  ( sendFile
  )
where

import Protolude

import System.Posix.Files
  ( getFileStatus
  , fileSize
  )
import System.Posix.Types
  ( FileOffset
  )
import Data.Aeson
  ( encode
  , eitherDecode
  )
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Hash as Hash
import Crypto.Saltine.Internal.ByteSizes (boxNonce)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder(toLazyByteString, word32BE)
import qualified Crypto.Spake2 as Spake2
import qualified MagicWormhole
import Data.Binary.Get (getWord32be, runGet)

import Transit.Internal.Network
import Transit.Internal.Peer
import Transit.Internal.Messages

type Password = ByteString

getFileSize :: FilePath -> IO FileOffset
getFileSize file = fileSize <$> getFileStatus file

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

-- |'transitExchange' exchanges transit message with the peer.
-- Sender sends a transit message with its abilities and hints.
-- Receiver sends either another Transit message or an Error message.
transitExchange :: MagicWormhole.EncryptedConnection -> IO (Either Text TransitMsg)
transitExchange conn = do
  (_, rxMsg) <- concurrently sendTransitMsg receiveTransitMsg
  case eitherDecode (toS rxMsg) of
    Right t@(Transit _ _) -> return (Right t)
    Left s -> return (Left (toS s))
    Right (Error errstr) -> return (Left errstr)
    Right (Answer _) -> return (Left "Answer message from the peer is unexpected")
  where
    sendTransitMsg = do
      -- create abilities
      let abilities' = [Ability DirectTcpV1]
      port' <- allocateTcpPort
      hints' <- buildDirectHints

      -- create transit message
      let txTransitMsg = Transit abilities' hints'
      let encodedTransitMsg = toS (encode txTransitMsg)

      -- send the transit message (dictionary with key as "transit" and value as abilities)
      MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)
    receiveTransitMsg = do
      -- receive the transit from the receiving side
      MagicWormhole.PlainText responseMsg <- atomically $ MagicWormhole.receiveMessage conn
      return responseMsg

offerExchange :: MagicWormhole.EncryptedConnection -> FilePath -> IO (Either Text ())
offerExchange conn path = do
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

handshakeExchange :: TCPEndpoint -> SecretBox.Key -> IO ()
handshakeExchange ep key = do
  (s, r) <- concurrently sendHandshake rxHandshake
  if r == rHandshakeMsg
    then
    sendGo >> return ()
    else
    sendNeverMind >> return ()
      where
        sendHandshake = sendBuffer ep sHandshakeMsg
        rxHandshake = recvBuffer ep (BS.length rHandshakeMsg)
        sendGo = sendBuffer ep (toS @Text @ByteString "go\n")
        sendNeverMind = sendBuffer ep (toS @Text @ByteString "nevermind\n")
        sHandshakeMsg = makeSenderHandshake key
        rHandshakeMsg = makeReceiverHandshake key

-- | encrypt the given chunk with the given secretbox key and nonce.
-- Saltine's nonce seem represented as a big endian bytestring.
-- However, to interop with the wormhole python client, we need to
-- use and send nonce as a little endian bytestring.
encrypt :: SecretBox.Key -> SecretBox.Nonce -> ByteString -> ByteString
encrypt key nonce plaintext =
  let nonceLE = BS.reverse $ Saltine.encode nonce
      newNonce = fromMaybe (panic "nonce decode failed") $
                 Saltine.decode nonceLE
      ciphertext = SecretBox.secretbox key newNonce plaintext
  in
    nonceLE <> ciphertext

decrypt :: SecretBox.Key -> ByteString -> Either Text ByteString
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

type PlainText = ByteString
type CipherText = ByteString

-- | Given the record encryption key and a bytestream, chop
-- the bytestream into blocks of 4096 bytes, encrypt them and
-- send it to the given network endpoint. The length of the
-- encrypted record is sent first, encoded as a 4-byte
-- big-endian number. After that, the encrypted record itself
-- is sent. `sendRecords` returns the SHA256 hash of the encrypted
-- file, which can be compared with the recipient's sha256 hash.
sendRecords :: TCPEndpoint -> SecretBox.Key -> ByteString -> IO Text
sendRecords ep key fileStream = do
  forM_ records sendRecord
  return $ show (sha256sum blocks)
  where
    records = go Saltine.zero blocks
    blocks = chop 4096 fileStream
    go :: SecretBox.Nonce -> [PlainText] -> [CipherText]
    go _ [] = []
    go nonce (chunk:restOfFile) =
      let cipherText = encrypt key nonce chunk
      in
        (cipherText): go (Saltine.nudge nonce) restOfFile
    chop sz fileBS | fileBS == BS.empty = []
                   | otherwise =
                     let (chunk, chunks) = BS.splitAt sz fileBS
                     in
                       chunk: chop sz chunks
    sendRecord :: ByteString -> IO ()
    sendRecord record = do
      -- send size of the encrypted payload as 4 bytes, then send record
      -- format sz as a fixed 4 byte bytestring
      let payloadSize = toLazyByteString (word32BE (fromIntegral (BS.length record)))
      _ <- sendBuffer ep (toS payloadSize)
      _ <- sendBuffer ep record
      return ()
    sha256sum :: [ByteString] -> Hash.Digest Hash.SHA256
    sha256sum = hashBlocks (Hash.hashInitWith Hash.SHA256)
      where
        hashBlocks :: Hash.Context Hash.SHA256 -> [ByteString] -> Hash.Digest Hash.SHA256
        hashBlocks ctx [] = Hash.hashFinalize ctx
        hashBlocks ctx (r:rs) = hashBlocks (Hash.hashUpdate ctx r) rs

receiveRecord :: TCPEndpoint -> SecretBox.Key -> IO ByteString
receiveRecord ep key = do
  -- read 4 bytes that consists of length
  -- read as much bytes specified by the length. That would be encrypted record
  -- decrypt the record
  lenBytes <- recvBuffer ep 4
  let len = runGet getWord32be (BL.fromStrict lenBytes)
  encRecord <- recvBuffer ep (fromIntegral len)
  case decrypt key encRecord of
    Left s -> panic s
    Right pt -> return pt

receiveAckMessage :: TCPEndpoint -> SecretBox.Key -> IO (Either Text Text)
receiveAckMessage ep key = do
  ackBytes <- BL.fromStrict <$> receiveRecord ep key
  case eitherDecode ackBytes of
    Right (TransitAck msg checksum) | msg == "ok" -> return (Right checksum)
                                    | otherwise -> return (Left "transit ack failure")
    Left s -> return (Left $ toS ("transit ack failure: " <> s))

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
sendFile :: MagicWormhole.Session -> MagicWormhole.AppID -> Password -> (Text -> IO ()) -> FilePath -> IO ()
sendFile session appid password printHelpFn filepath = do
  -- first establish a wormhole session with the receiver and
  -- then talk the filetransfer protocol over it as follows.
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printHelpFn $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        -- exchange abilities
        transitResp <- transitExchange conn
        case transitResp of
          Left s -> panic s
          Right (Transit peerAbilities peerHints) -> do
            -- send offer for the file
            offerResp <- offerExchange conn filepath
            fileBytes <- BS.readFile filepath
            case offerResp of
              Left s -> panic s
              Right _ -> do
                runTransitProtocol peerAbilities peerHints
                  (\endpoint -> do
                     -- 0. derive transit key
                     let sessionKey = MagicWormhole.sharedKey conn
                         transitKey = MagicWormhole.deriveKey sessionKey (transitPurpose appid)
                     -- 1. handshakeExchange
                     handshakeExchange endpoint transitKey
                     -- 2. create record keys
                     let sRecordKey = makeSenderRecordKey transitKey
                     -- 3. send encrypted chunks of N bytes to the peer
                     txSha256Hash <- sendRecords endpoint sRecordKey fileBytes
                     -- 4. TODO: read a record that should contain the transit Ack.
                     --    If ack is not ok or the sha256sum is incorrect, flag an error.
                     let rRecordKey = makeReceiverRecordKey transitKey
                     rxAckMsg <- receiveAckMessage endpoint rRecordKey
                     case rxAckMsg of
                       Right rxSha256Hash ->
                         if txSha256Hash /= rxSha256Hash
                         then panic "sha256 mismatch"
                         else
                           return ()
                       Left e -> panic e
                     )
          Right _ -> panic "error sending transit message"
    )

