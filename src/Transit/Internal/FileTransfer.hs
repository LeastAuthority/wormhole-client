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
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified Conduit as C

import Network.Socket (socketPort)

import qualified MagicWormhole

import Transit.Internal.Network
  ( allocateTcpPort
  , buildDirectHints
  , startServer
  , startClient
  , closeConnection
  , CommunicationError(..))
import Transit.Internal.Peer
  ( transitExchange
  , senderOfferExchange
  , makeSenderRecordKey
  , makeReceiverRecordKey
  , senderHandshakeExchange
  , receiveAckMessage
  , receiveWormholeMessage
  , sendTransitMsg
  , sendWormholeMessage
  , receiverHandshakeExchange
  , sendGoodAckMessage)
import Transit.Internal.Messages
  ( TransitMsg( Transit, Answer )
  , Ability(..)
  , AbilityV1(..)
  , Ack( FileAck ))
import Transit.Internal.Pipeline
  ( sendPipeline
  , receivePipeline)

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
            -- wait for "answer" message with "message_ack" key
            MagicWormhole.PlainText rxTransitMsg <- atomically $ MagicWormhole.receiveMessage conn
            case Aeson.eitherDecode (toS rxTransitMsg) of
              Left s -> throwIO (TransitError (show s))
              Right (Answer (MessageAck msg')) | msg' == "ok" -> return ()
                                               | otherwise -> throwIO (TransitError "Message ack failed")
              Right s -> throwIO (TransitError (show s))
          TFile filepath -> do
            -- exchange abilities
            sock' <- tcpListener
            portnum <- socketPort sock'
            withAsync (startServer sock') $ \asyncServer -> do
              transitResp <- transitExchange conn portnum
              case transitResp of
                Left s -> throwIO (TransitError s)
                Right (Transit peerAbilities peerHints) -> do
                  -- send offer for the file
                  offerResp <- senderOfferExchange conn filepath
                  case offerResp of
                    Left s -> throwIO (OfferError s)
                    Right _ ->
                      withAsync (startClient peerHints) $ \asyncClient -> do
                        ep <- waitAny [asyncServer, asyncClient]
                        let endpoint = snd ep
                        -- 0. derive transit key
                        let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                        -- 1. create record keys
                            maybeRecordKeys = (,) <$> makeSenderRecordKey transitKey
                                              <*> makeReceiverRecordKey transitKey
                        case maybeRecordKeys of
                          Nothing -> throwIO (TransitError "could not create record keys")
                          Just (sRecordKey, rRecordKey) -> do
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
                                throwIO (Sha256SumError "sha256 mismatch")
                              Left e -> throwIO (ConnectionError e)
                Right _ -> throwIO (ConnectionError "error sending transit message")
    )

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
        -- If the sender is only sending a text message, it gets an offer first.
        -- if the sender is sending a file/directory, then transit comes first
        -- and then offer comes in.
        received <- receiveWormholeMessage conn
        case Aeson.eitherDecode (toS received) of
          Right (MagicWormhole.Message message) -> do
            -- TODO: send answer message with message_ack
            TIO.putStrLn message
          Right (MagicWormhole.File _ _) -> do
            -- TODO: send answer with message_ack not_ok
            throwIO (ConnectionError "did not expect a file offer")
          -- ok, we received the Transit Message, send back a transit message
          Left _ ->
            case Aeson.eitherDecode (toS received) of
              Left err -> throwIO (TransitError (toS err))
              Right (Transit peerAbilities peerHints) -> do
                let abilities' = [Ability DirectTcpV1]
                s <- tcpListener
                portnum <- socketPort s
                hints' <- buildDirectHints portnum
                withAsync (startServer s) $ \asyncServer -> do
                  sendTransitMsg conn abilities' hints'
                  -- now expect an offer message
                  offerMsg <- receiveWormholeMessage conn
                  case Aeson.eitherDecode (toS offerMsg) of
                    Left err -> throwIO (OfferError $ "unable to decode offer msg: " <> toS err)
                    Right (MagicWormhole.File name size) -> do
                      -- TODO: if the file already exist in the current dir, abort
                      -- send an answer message with file_ack.
                      let ans = Answer (FileAck "ok")
                      sendWormholeMessage conn (Aeson.encode ans)
                      -- runTransitProtocol peerAbilities peerHints asyncServer
                      withAsync (startClient peerHints) $ \asyncClient -> do
                        ep <- waitAny [asyncServer, asyncClient]
                        let endpoint = snd ep
                        -- 0. derive transit key
                        let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                        -- 1. handshakeExchange
                        receiverHandshakeExchange endpoint transitKey
                        -- 2. create sender/receiver record key, sender record key
                        --    for decrypting incoming records, receiver record key
                        --    for sending the file_ack back at the end.
                        let maybeRecordKeys = (,) <$> makeSenderRecordKey transitKey
                                              <*> makeReceiverRecordKey transitKey
                        case maybeRecordKeys of
                          Nothing -> throwIO (TransitError "could not create record keys")
                          Just (sRecordKey, rRecordKey) -> do
                            -- 3. receive and decrypt records (length followed by length
                            --    sized packets). Also keep track of decrypted size in
                            --    order to know when to send the file ack at the end.
                            (rxSha256Sum, ()) <- C.runConduitRes $ receivePipeline name (fromIntegral size) endpoint sRecordKey
                            TIO.putStrLn (show rxSha256Sum)
                            sendGoodAckMessage endpoint rRecordKey (toS rxSha256Sum)
                            -- close the connection
                            closeConnection endpoint

                    Right (MagicWormhole.Directory _ _ _ _ _) -> throwIO (UnknownPeerMessage "Directory offers are not supported yet")
                    Right _ -> throwIO (UnknownPeerMessage "Could not decode message")
              Right _ -> throwIO (UnknownPeerMessage "Could not decode message")
    )
