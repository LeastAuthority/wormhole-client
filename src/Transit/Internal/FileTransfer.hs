{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.FileTransfer
  ( sendFile
  , receiveFile
  , MessageType(..)
  )
where

import Protolude

import qualified Data.Aeson as Aeson
import qualified Data.Text.IO as TIO
import qualified Conduit as C

import Network.Socket (socketPort)

import qualified MagicWormhole

import Transit.Internal.Network
  ( tcpListener
  , buildDirectHints
  , startServer
  , startClient
  , closeConnection
  , RelayEndpoint
  , CommunicationError(..))

import Transit.Internal.Peer
  ( makeSenderRecordKey
  , makeReceiverRecordKey
  , senderHandshakeExchange
  , senderTransitExchange
  , senderFileOfferExchange
  , receiveAckMessage
  , receiveWormholeMessage
  , sendTransitMsg
  , sendWormholeMessage
  , receiverHandshakeExchange
  , sendGoodAckMessage
  , generateTransitSide)

import Transit.Internal.Messages
  ( TransitMsg( Transit, Answer )
  , Ability(..)
  , AbilityV1(..)
  , Ack( FileAck ))

import Transit.Internal.Pipeline
  ( sendPipeline
  , receivePipeline)

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
sendFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> MagicWormhole.AppID -> FilePath -> IO ()
sendFile conn transitserver appid filepath = do
  -- exchange abilities
  sock' <- tcpListener
  portnum <- socketPort sock'
  side <- generateTransitSide
  withAsync (startServer sock') $ \asyncServer -> do
    transitResp <- senderTransitExchange conn transitserver portnum
    case transitResp of
      Left s -> throwIO (TransitError s)
      Right (Transit peerAbilities peerHints) -> do
        -- send offer for the file
        offerResp <- senderFileOfferExchange conn filepath
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
                senderHandshakeExchange endpoint transitKey side

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


receiveFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> MagicWormhole.AppID -> TransitMsg -> IO ()
receiveFile conn transitserver appid (Transit peerAbilities peerHints) = do
  let abilities' = [Ability DirectTcpV1, Ability RelayV1]
  s <- tcpListener
  portnum <- socketPort s
  hints' <- buildDirectHints portnum
  side <- generateTransitSide
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
          receiverHandshakeExchange endpoint transitKey side
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
      Right _ -> throwIO (UnknownPeerMessage "Could not decode message")
receiveFile _ _ _ _ = throwIO (UnknownPeerMessage "Could not recognize the message")

