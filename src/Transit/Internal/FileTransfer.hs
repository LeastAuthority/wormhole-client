{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.FileTransfer
  ( sendFile
  , receiveFile
  , MessageType(..)
  )
where

import Protolude

import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Data.Aeson as Aeson
import qualified Data.Text.IO as TIO
import qualified Conduit as C
import qualified Data.Set as Set
import qualified Data.ByteString.Lazy as BL

import Network.Socket (socketPort)

import qualified MagicWormhole

import Transit.Internal.Errors (Error(..))
import Transit.Internal.Crypto (CipherText(..))
import Transit.Internal.Network
  ( tcpListener
  , buildHints
  , buildRelayHints
  , startServer
  , startClient
  , closeConnection
  , RelayEndpoint
  , CommunicationError(..)
  , TCPEndpoint
  , TransitEndpoint(..))

import Transit.Internal.Peer
  ( makeRecordKeys
  , senderHandshakeExchange
  , senderTransitExchange
  , senderFileOfferExchange
  , receiveWormholeMessage
  , sendTransitMsg
  , sendWormholeMessage
  , receiverHandshakeExchange
  , makeGoodAckMessage
  , generateTransitSide
  , sendRecord
  , receiveRecord)

import Transit.Internal.Messages
  ( TransitMsg( Transit, Answer )
  , Ability(..)
  , AbilityV1(..)
  , Ack( FileAck )
  , TransitAck (..))

import Transit.Internal.Pipeline
  ( sendPipeline
  , receivePipeline)

data MessageType
  = TMsg Text
  | TFile FilePath
  deriving (Show, Eq)

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

sendGoodAckMessage :: TCPEndpoint -> SecretBox.Key -> ByteString -> IO (Either Error ())
sendGoodAckMessage ep key sha256Sum = do
  let goodAckMessage = makeGoodAckMessage key sha256Sum
  case goodAckMessage of
    Right (CipherText encMsg) -> do
      res <- sendRecord ep encMsg
      return $ bimap GeneralError (const ()) res
    Left e -> return $ Left (CipherError e)

receiveAckMessage :: TCPEndpoint -> SecretBox.Key -> IO (Either Error Text)
receiveAckMessage ep key = do
  ackBytes <- (fmap . fmap) BL.fromStrict (receiveRecord ep key)
  case ackBytes of
    Left e -> return $ Left (CipherError e)
    Right ack' ->
      case Aeson.eitherDecode ack' of
        Right (TransitAck msg checksum) | msg == "ok" -> return (Right checksum)
                                        | otherwise -> return $ Left (GeneralError (TransitError "transit ack failure"))
        Left s -> return $ Left (GeneralError (TransitError (toS ("transit ack failure: " <> s))))

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
sendFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> MagicWormhole.AppID -> FilePath -> IO (Either Error ())
sendFile conn transitserver appid filepath = do
  -- exchange abilities
  sock' <- tcpListener
  portnum <- socketPort sock'
  side <- generateTransitSide
  withAsync (startServer sock') $ \asyncServer -> do
    ourHints <- buildHints portnum transitserver
    let ourRelayHints = buildRelayHints transitserver
    transitResp <- senderTransitExchange conn (Set.toList ourHints)
    case transitResp of
      Left s -> return $ Left (GeneralError s)
      Right (Transit _peerAbilities peerHints) -> do
        -- send offer for the file
        offerResp <- senderFileOfferExchange conn filepath
        case offerResp of
          Left s -> return (Left (GeneralError (OfferError s)))
          Right _ -> do
            -- combine our relay hints with peer's direct and relay hints
            let allHints = Set.toList $ ourRelayHints <> peerHints
            withAsync (startClient allHints) $ \asyncClient -> do
              ep <- waitAny [asyncServer, asyncClient]
              let endpoint' = snd ep
              case endpoint' of
                Left e -> return (Left (GeneralError e))
                Right endpoint -> do
                  -- 0. derive transit key
                  let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                  -- 1. create record keys
                      recordKeys = makeRecordKeys transitKey
                  case recordKeys of
                    Left e -> return (Left (CipherError e))
                    Right (sRecordKey, rRecordKey) -> do
                      -- 2. handshakeExchange
                      handshake <- senderHandshakeExchange endpoint transitKey side
                      case handshake of
                        Left e -> return (Left (HandshakeError e))
                        Right _ -> do
                          -- 3. send encrypted chunks of N bytes to the peer
                          (txSha256Hash, _) <- C.runConduitRes (sendPipeline filepath endpoint sRecordKey)
                          -- 4. read a record that should contain the transit Ack.
                          --    If ack is not ok or the sha256sum is incorrect, flag an error.
                          rxAckMsg <- receiveAckMessage endpoint rRecordKey
                          closeConnection endpoint
                          case rxAckMsg of
                            Right rxSha256Hash ->
                              if (txSha256Hash /= rxSha256Hash)
                              then return $ Left (GeneralError (Sha256SumError "sha256 mismatch"))
                              else return (Right ())
                            Left e -> return $ Left e
      Right _ -> return $ Left (GeneralError (ConnectionError "error sending transit message"))

receiveFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> MagicWormhole.AppID -> TransitMsg -> IO (Either Error ())
receiveFile conn transitserver appid (Transit _peerAbilities peerHints) = do
  let abilities' = [Ability DirectTcpV1, Ability RelayV1]
  s <- tcpListener
  portnum <- socketPort s
  ourHints <- buildHints portnum transitserver
  let ourRelayHints = buildRelayHints transitserver
  side <- generateTransitSide
  withAsync (startServer s) $ \asyncServer -> do
    sendTransitMsg conn abilities' (Set.toList ourHints)
    -- now expect an offer message
    offerMsg <- receiveWormholeMessage conn
    case Aeson.eitherDecode (toS offerMsg) of
      Left err -> return $ Left (GeneralError (OfferError $ "unable to decode offer msg: " <> toS err))
      Right (MagicWormhole.File name size) -> do
        -- TODO: if the file already exist in the current dir, abort
        -- send an answer message with file_ack.
        let ans = Answer (FileAck "ok")
        sendWormholeMessage conn (Aeson.encode ans)
        -- combine our relay hints with peer's direct and relay hints
        let allHints = Set.toList (peerHints <> ourRelayHints)
        withAsync (startClient allHints) $ \asyncClient -> do
          ep <- waitAny [asyncServer, asyncClient]
          let endpoint' = snd ep
          case endpoint' of
            Left e -> return (Left (GeneralError e))
            Right endpoint -> do
              -- 0. derive transit key
              let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
              -- 1. handshakeExchange
              handshake <- receiverHandshakeExchange endpoint transitKey side
              case handshake of
                Left e -> return (Left (HandshakeError e))
                Right _ -> do
                  -- 2. create sender/receiver record key, sender record key
                  --    for decrypting incoming records, receiver record key
                  --    for sending the file_ack back at the end.
                  let recordKeys = makeRecordKeys transitKey
                  case recordKeys of
                    Left e -> return $ Left (CipherError e)
                    Right (sRecordKey, rRecordKey) -> do
                      -- 3. receive and decrypt records (length followed by length
                      --    sized packets). Also keep track of decrypted size in
                      --    order to know when to send the file ack at the end.
                      (rxSha256Sum, ()) <- C.runConduitRes $ receivePipeline name (fromIntegral size) endpoint sRecordKey
                      TIO.putStrLn (show rxSha256Sum)
                      _ <- sendGoodAckMessage endpoint rRecordKey (toS rxSha256Sum)
                      -- close the connection
                      Right <$> closeConnection endpoint
      Right _ -> return $ Left (GeneralError (UnknownPeerMessage "Could not decode message"))
receiveFile _ _ _ _ = return $ Left (GeneralError (UnknownPeerMessage "Could not recognize the message"))

establishSenderTransit :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> MagicWormhole.AppID -> IO (Either Error TransitEndpoint)
establishSenderTransit conn transitserver appid = do
  -- exchange abilities
  sock' <- tcpListener
  portnum <- socketPort sock'
  side <- generateTransitSide
  ourHints <- buildHints portnum transitserver
  let ourRelayHints = buildRelayHints transitserver
  transitResp <- senderTransitExchange conn (Set.toList ourHints)
  case transitResp of
    Left s -> return $ Left (GeneralError s)
    Right (Transit _peerAbilities peerHints) -> do
      -- combine our relay hints with peer's direct and relay hints
      let allHints = Set.toList $ ourRelayHints <> peerHints
      -- concurrently start client and server
      transitEndpoint <- race (startServer sock') (startClient allHints)
      let ep = either identity identity transitEndpoint
      case ep of
        Left e -> return (Left (GeneralError e))
        Right endpoint -> do
          -- 0. derive transit key
          let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
              -- 1. create record keys
              recordKeys = makeRecordKeys transitKey
          case recordKeys of
            Left e -> return (Left (CipherError e))
            Right (sRecordKey, rRecordKey) -> do
              -- 2. handshakeExchange
              handshake <- senderHandshakeExchange endpoint transitKey side
              -- if handshakeExchange is successful, return the TCPEndpoint
              -- as, we now have a "secure" socket to communicate.
              case handshake of
                Left e -> return (Left (HandshakeError e))
                Right _ -> return $ Right (TransitEndpoint endpoint sRecordKey rRecordKey)
    Right _ -> return $ Left (GeneralError (UnknownPeerMessage "Could not decode message"))
