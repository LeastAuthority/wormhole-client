{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.FileTransfer
  ( send
  , receive
  , MessageType(..)
  )
where

import Protolude

import qualified Crypto.Spake2 as Spake2
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import System.FilePath (takeFileName)
import System.IO (openTempFile, hClose)
import System.PosixCompat.Files (rename)
import qualified Data.Conduit.Network as CN
import qualified Conduit as C
import Data.Conduit ((.|))
import qualified Crypto.Saltine.Core.SecretBox as SecretBox

import qualified MagicWormhole

import Transit.Internal.Network
import Transit.Internal.Peer
import Transit.Internal.Messages

type Password = ByteString

data MessageType
  = TMsg Text
  | TFile FilePath
  deriving (Show, Eq)

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
send :: MagicWormhole.Session -> MagicWormhole.AppID -> Password -> (Text -> IO ()) -> MessageType -> IO ()
send session appid password printHelpFn tfd = do
  -- first establish a wormhole session with the receiver and
  -- then talk the filetransfer protocol over it as follows.
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printHelpFn $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn ->
        case tfd of
          TMsg msg -> do
            let offer = MagicWormhole.Message msg
            MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (Aeson.encode offer)))
          TFile filepath -> do
            -- exchange abilities
            portnum <- allocateTcpPort
            _ <- withAsync (startServer portnum)
                 (\asyncServer -> do
                     transitResp <- transitExchange conn portnum
                     case transitResp of
                       Left s -> panic s
                       Right (Transit peerAbilities peerHints) -> do
                         -- send offer for the file
                         offerResp <- senderOfferExchange conn filepath
                         case offerResp of
                           Left s -> panic s
                           Right _ ->
                             runTransitProtocol peerAbilities peerHints asyncServer
                             (\endpoint -> do
                                 -- 0. derive transit key
                                 let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                                 -- 1. create record keys
                                     sRecordKey = makeSenderRecordKey transitKey
                                     rRecordKey = makeReceiverRecordKey transitKey
                                 -- 2. handshakeExchange
                                 senderHandshakeExchange endpoint transitKey
                                 -- 3. send encrypted chunks of N bytes to the peer
                                 (txSha256Hash, _) <- C.runConduitRes (sendPipeline filepath endpoint sRecordKey)
                                 -- 4. read a record that should contain the transit Ack.
                                 --    If ack is not ok or the sha256sum is incorrect, flag an error.
                                 rxAckMsg <- receiveAckMessage endpoint rRecordKey
                                 closeConnection endpoint
                                 case rxAckMsg of
                                   Right rxSha256Hash ->
                                     when (txSha256Hash /= rxSha256Hash) $
                                     panic "sha256 mismatch"
                                   Left e -> panic e
                             )
                       Right _ -> panic "error sending transit message"
                 )
            return ()
    )

sendPipeline :: C.MonadResource m =>
                FilePath
             -> TCPEndpoint
             -> SecretBox.Key
             -> C.ConduitM a c m (Text, ())
sendPipeline fp (TCPEndpoint s) key =
  C.sourceFile fp .| sha256PassThroughC `C.fuseBoth` (encryptC key .| CN.sinkSocket s)

-- | receive a text message or file from the wormhole peer.
receive :: MagicWormhole.Session -> MagicWormhole.AppID -> Text -> IO ()
receive session appid code = do
  -- establish the connection
  let codeSplit = Text.split (=='-') code
  let (Just nameplate) = headMay codeSplit
  mailbox <- MagicWormhole.claim session (MagicWormhole.Nameplate nameplate)
  peer <- MagicWormhole.open session mailbox
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS (Text.strip code)))
    (\conn -> do
        -- unfortunately, the receiver has no idea which message to expect.
        -- If the sender is only sending a text message, it gets an offer first
        -- if the sender is sending a file/directory, then transit comes first
        -- and then offer comes in.
        received <- receiveWormholeMessage conn
        case Aeson.eitherDecode (toS received) of
          Right (MagicWormhole.Message message) -> TIO.putStrLn message
          Right (MagicWormhole.File _ _) -> panic "did not expect a file offer"
          -- ok, we received the Transit Message, send back a transit message
          Left _ ->
            case Aeson.eitherDecode (toS received) of
              Left err -> panic (show err)
              Right (Transit peerAbilities peerHints) -> do
                let abilities' = [Ability DirectTcpV1]
                portnum <- allocateTcpPort
                hints' <- buildDirectHints portnum
                withAsync (startServer portnum)
                  (\asyncServer -> do
                      sendTransitMsg conn abilities' hints'
                      -- now expect an offer message
                      offerMsg <- receiveWormholeMessage conn
                      case Aeson.eitherDecode (toS offerMsg) of
                        Left err -> panic ("unable to decode offer msg" <> show err)
                        Right (MagicWormhole.File name size) -> do
                          -- TODO: if the file already exist in the current dir, abort
                          -- send an answer message with file_ack.
                          let ans = Answer (FileAck "ok")
                          sendWormholeMessage conn (Aeson.encode ans)
                          runTransitProtocol peerAbilities peerHints asyncServer
                            (\endpoint -> do
                                -- 0. derive transit key
                                let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                                -- 1. handshakeExchange
                                receiverHandshakeExchange endpoint transitKey
                                -- 2. create sender/receiver record key, sender record key
                                --    for decrypting incoming records, receiver record key
                                --    for sending the file_ack back at the end.
                                let sRecordKey = makeSenderRecordKey transitKey
                                    rRecordKey = makeReceiverRecordKey transitKey
                                -- 3. receive and decrypt records (length followed by length
                                --    sized packets). Also keep track of decrypted size in
                                --    order to know when to send the file ack at the end.
                                decRecords <- receiveRecords endpoint sRecordKey (fromIntegral size)
                                writeRecordsToFile name decRecords
                                let sha256' = sha256sum decRecords
                                TIO.putStrLn (show sha256')
                                sendGoodAckMessage endpoint rRecordKey (show sha256')
                                -- close the connection
                                closeConnection endpoint
                            )
                        Right _ -> panic "Could not decode message"
                  )
              Right _ -> panic "Could not decode message"
    )

writeRecordsToFile :: FilePath -> [ByteString] -> IO ()
writeRecordsToFile path records =
  bracket
    (openTempFile "./" (takeFileName path))
    (\(name, htemp) -> do
        rename name (takeFileName path)
        hClose htemp)
    (\(_, htemp) -> BS.hPut htemp (BS.concat records))
