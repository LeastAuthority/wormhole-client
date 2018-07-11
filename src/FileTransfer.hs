{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
module FileTransfer
  ( sendFile
  )
where

import Protolude

import qualified Data.ByteString as BS
import qualified Crypto.Spake2 as Spake2

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
                     let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
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

