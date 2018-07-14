{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module FileTransfer
  ( sendFile
  , receive
  )
where

import Protolude

import qualified Data.ByteString as BS
import qualified Crypto.Spake2 as Spake2
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified Data.Aeson as Aeson

import qualified MagicWormhole

import Transit.Internal.Network
import Transit.Internal.Peer
import Transit.Internal.Messages

type Password = ByteString

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

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
        port <- allocateTcpPort
        transitResp <- transitExchange conn port
        case transitResp of
          Left s -> panic s
          Right (Transit peerAbilities peerHints) -> do
            -- send offer for the file
            offerResp <- offerExchange conn filepath
            fileBytes <- BS.readFile filepath
            case offerResp of
              Left s -> panic s
              Right _ -> do
                runTransitProtocol peerAbilities peerHints port
                  (\endpoint -> do
                     -- 0. derive transit key
                     let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                     -- 1. handshakeExchange
                     senderHandshakeExchange endpoint transitKey
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
                         else return ()
                       Left e -> panic e
                     )
          Right _ -> panic "error sending transit message"
    )

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
        MagicWormhole.PlainText received <- atomically $ MagicWormhole.receiveMessage conn
        case Aeson.eitherDecode (toS received) of
          Right (MagicWormhole.Message message) -> TIO.putStrLn message
          -- ok, we received the Transit Message, send back a transit message
          Left err -> do
            case Aeson.eitherDecode (toS received) of
              Right t@(Transit peerAbilities peerHints) -> do
                let abilities' = [Ability DirectTcpV1]
                port <- allocateTcpPort
                hints' <- buildDirectHints port
                sendTransitMsg conn abilities' hints'
                -- now expect an offer message
                MagicWormhole.PlainText offerMsg <- atomically $ MagicWormhole.receiveMessage conn
                case Aeson.eitherDecode (toS offerMsg) of
                  Left err -> panic "unable to decode offer msg"
                  Right o@(MagicWormhole.File name size) -> do
                    -- TODO: if the file already exist in the current dir, abort
                    -- send an answer message with file_ack.
                    let ans = Answer (FileAck "ok")
                    MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (Aeson.encode ans)))
                    -- TODO: a tcp listener must be up and running at this point.
                    -- TCPEndpoint
                    runTransitProtocol peerAbilities peerHints port
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
                          -- 3. receive and decrypt records (length followed by length sized packets)
                          --    Also keep track of decrypted size in order to know when to send the
                          --    file ack at the end.
                          sha256Sum <- receiveRecords endpoint sRecordKey name size
                          TIO.putStrLn (toS sha256Sum)
                          sendGoodAckMessage endpoint rRecordKey sha256Sum
                          -- TODO: close listening and connecting sockets
                          return ()
                      )
                  Right _ -> panic $ "Could not decode message"
          Right _ -> panic $ "Could not decode message"
    )

