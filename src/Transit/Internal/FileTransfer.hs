-- | Description: Functions for sending and receiving files/directories
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module Transit.Internal.FileTransfer
  ( sendFile
  , receiveFile
  , MessageType(..)
  )
where

import Protolude hiding (toS)
import Protolude.Conv (toS)

import qualified Data.Aeson as Aeson
import qualified Conduit as C
import qualified Data.Set as Set
import qualified Data.ByteString.Lazy as BL
import qualified Crypto.Saltine.Core.SecretBox as SecretBox

import Network.Socket (Socket)
import System.FilePath ((</>), takeFileName)
import System.Directory (removeFile, getTemporaryDirectory)
import System.IO.Temp (createTempDirectory)

import qualified MagicWormhole

import Transit.Internal.Errors (Error(..))
import Transit.Internal.Crypto (CipherText(..))
import Transit.Internal.Network
  ( tcpListener
  , getSocketPort
  , buildHints
  , buildRelayHints
  , startServer
  , startClient
  , closeConnection
  , RelayEndpoint
  , CommunicationError(..)
  , TransitEndpoint(..))

import Transit.Internal.Peer
  ( makeRecordKeys
  , handshakeExchange
  , senderTransitExchange
  , senderOfferExchange
  , receiveWormholeMessage
  , sendTransitMsg
  , sendWormholeMessage
  , makeAckMessage
  , generateTransitSide
  , sendRecord
  , receiveRecord
  , unzipInto
  , Mode(..))

import Transit.Internal.Messages
  ( TransitMsg( Transit, Answer )
  , Ability(..)
  , AbilityV1(..)
  , Ack( FileAck )
  , TransitAck (..))

import Transit.Internal.Pipeline
  ( sendPipeline
  , receivePipeline)

-- | Transfer type
data MessageType
  = TMsg Text
    -- ^ Text message transfer
  | TFile FilePath
    -- ^ File or Directory transfer
  deriving (Show, Eq)

sendAckMessage :: TransitEndpoint -> ByteString -> IO (Either Error ())
sendAckMessage (TransitEndpoint ep _ key) sha256Sum = do
  let ackMessage = makeAckMessage key sha256Sum
  case ackMessage of
    Right (CipherText encMsg) -> do
      res <- sendRecord ep encMsg
      return $ bimap NetworkError (const ()) res
    Left e -> return $ Left (CipherError e)

receiveAckMessage :: TransitEndpoint -> IO (Either Error Text)
receiveAckMessage (TransitEndpoint ep _ key) = do
  ackBytes <- (fmap . fmap) BL.fromStrict (receiveRecord ep key)
  case ackBytes of
    Left e -> return $ Left (CipherError e)
    Right ack' ->
      case Aeson.eitherDecode ack' of
        Right (TransitAck msg checksum) | msg == "ok" -> return (Right checksum)
                                        | otherwise -> return $ Left (NetworkError (TransitError "transit ack failure"))
        Left s -> return $ Left (NetworkError (TransitError (toS ("transit ack failure: " <> s))))

establishTransit :: Mode -> RelayEndpoint -> SecretBox.Key -> TransitMsg -> Maybe Socket -> IO (Either Error TransitEndpoint)
establishTransit mode transitserver transitKey (Transit _peerAbilities peerHints) socket = do
  let ourRelayHints = buildRelayHints transitserver
  side <- generateTransitSide
  -- combine our relay hints with peer's direct and relay hints
  let allHints = Set.toList (peerHints <> ourRelayHints)
  -- concurrently start client and server
  ep <- case socket of
          Nothing -> startClient allHints
          Just sock' -> do
            transitEndpoint <- race (startServer sock') (startClient allHints)
            return $ either identity identity transitEndpoint
  case ep of
    Left e -> return (Left (NetworkError e))
    Right endpoint -> do
      -- 1. create record keys
      let recordKeys = makeRecordKeys transitKey
      case recordKeys of
        Left e -> return (Left (CipherError e))
        Right (sRecordKey, rRecordKey) -> do
          -- 2. handshakeExchange
          handshake <- handshakeExchange mode endpoint transitKey side
          -- if handshakeExchange is successful, return the TCPEndpoint
          -- as, we now have a "secure" socket to communicate.
          case handshake of
            Left e -> return (Left (HandshakeError e))
            Right _ -> return $ Right (TransitEndpoint endpoint sRecordKey rRecordKey)
establishTransit _ _ _ _ _ = return $ Left (NetworkError (UnknownPeerMessage "Could not decode message"))

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
sendFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> SecretBox.Key -> FilePath -> Bool -> FilePath -> IO (Either Error ())
sendFile conn transitserver transitKey filepath useTor tmpDirPath = do
    -- exchange abilities
  sock' <- tcpListener useTor
  portnum <- getSocketPort sock'
  ourHints <- buildHints portnum transitserver
  transitResp <- senderTransitExchange conn (Set.toList ourHints)
  case transitResp of
    Left s -> return $ Left (NetworkError s)
    Right transit -> do
      -- send offer for the file
      offerResp <- senderOfferExchange conn filepath tmpDirPath
      case offerResp of
        Left s -> return (Left (NetworkError (OfferError s)))
        Right filepath' -> do
          -- establish a transit connection
          endpoint <- establishTransit Send transitserver transitKey transit sock'
          case endpoint of
            Left e -> return $ Left e
            Right ep -> do
              (rxAckMsg, txSha256Hash) <-
                finally
                (do -- send encrypted records to the peer
                    (txSha256Hash, _) <- C.runConduitRes (sendPipeline filepath' ep)
                    -- read a record that should contain the transit Ack.
                    -- If ack is not ok or the sha256sum is incorrect, flag an error.
                    rxAckMsg <- receiveAckMessage ep
                    return (rxAckMsg, txSha256Hash))
                (closeConnection ep)
              case rxAckMsg of
                Right rxSha256Hash ->
                  if txSha256Hash /= rxSha256Hash
                  then return $ Left (NetworkError (Sha256SumError "sha256 mismatch"))
                  else return (Right ())
                Left e -> return $ Left e

-- | Receive a file or directory via the established MagicWormhole connection
receiveFile :: MagicWormhole.EncryptedConnection -> RelayEndpoint -> SecretBox.Key -> TransitMsg -> Bool -> IO (Either Error ())
receiveFile conn transitserver transitKey transit useTor = do
  let abilities' = [Ability DirectTcpV1, Ability TorTcpV1, Ability RelayV1]
  s <- tcpListener useTor
  portnum <- getSocketPort s
  ourHints <- buildHints portnum transitserver
  sendTransitMsg conn abilities' (Set.toList ourHints)
  -- now expect an offer message
  offerMsg <- receiveWormholeMessage conn
  case Aeson.eitherDecode (toS offerMsg) of
    Left err -> return $ Left (NetworkError (OfferError $ "unable to decode offer msg: " <> toS err))
    Right (MagicWormhole.File name size) -> rxFile s (takeFileName name) size
    Right (MagicWormhole.Directory _mode name zipSize _ _uncompressedSize) -> do
      systemTmpDir <- getTemporaryDirectory
      tmpDir <- createTempDirectory systemTmpDir "wormhole"
      let zipFile = tmpDir </> (toS name)
      _ <- rxFile s zipFile zipSize
      -- TODO: check if the file system containing the current directory has
      -- enough space, by checking the uncompressedSize and the free space.
      _ <- unzipInto (toS name) zipFile
      Right <$> removeFile zipFile
    Right _ -> return $ Left (NetworkError (UnknownPeerMessage "cannot decipher the message from peer"))
    where
      rxFile socket name size = do
        -- TODO: if the file already exist in the current dir, abort.
        -- send an answer message with file_ack.
        let ans = Answer (FileAck "ok")
        sendWormholeMessage conn (Aeson.encode ans)
        -- establish receive transit endpoint
        endpoint <- establishTransit Receive transitserver transitKey transit socket
        case endpoint of
          Left e -> return $ Left e
          Right ep -> do
            _ <- finally
                 (do
                     -- receive and decrypt records (length followed by length
                     -- sized packets). Also keep track of decrypted size in
                     -- order to know when to send the file ack at the end.
                     (rxSha256Sum, ()) <- C.runConduitRes $ receivePipeline name (fromIntegral size) ep
                     sendAckMessage ep (toS rxSha256Sum))
                 (closeConnection ep)
            return $ Right ()

