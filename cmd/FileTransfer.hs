{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
module FileTransfer
  (
    sendFile
  -- for tests
  , Ability(..)
  , AbilityV1(..)
  , Hint(..)
  , ConnectionHint(..)
--  , Transit(..)
  , Response(..)
  , Ack(..)
  )
where

import Protolude

import qualified Data.Text.IO as TIO
import qualified Crypto.Spake2 as Spake2


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

import qualified MagicWormhole
import FileTransfer.Internal.Network
import FileTransfer.Internal.Protocol

import Helper


type Password = ByteString


getFileSize :: FilePath -> IO FileOffset
getFileSize file = fileSize <$> getFileStatus file

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appID) = toS appID <> "/transit-key"

sendFile :: MagicWormhole.Session -> Password -> FilePath -> IO () -- Response
sendFile session password filepath = do
--   -- steps
--   -- * first establish a wormhole session with the receiver and
--   --   then talk the filetransfer protocol over it as follows.
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printSendHelpText $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        -- create abilities
        let abilities' = [Ability DirectTcpV1]
        port' <- allocateTcpPort
        let hint = Hint DirectTcpV1 0.0 "127.0.0.1" (fromIntegral (toInteger port'))
        let hints' = [Direct hint]
        -- create transit message
        let txTransitMsg = Transit abilities' hints'
        let encodedTransitMsg = toS (encode txTransitMsg)
        -- send the transit message (dictionary with key as "transit" and value as abilities)
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText encodedTransitMsg)

        -- receive the transit from the receiving side
        MagicWormhole.PlainText responseMsg <- atomically $ MagicWormhole.receiveMessage conn
        case (eitherDecode (toS responseMsg)) of
          Left s -> TIO.putStrLn ("unable to decode the response to transit msg: " <> (toS s))
          Right (Error errstr) -> TIO.putStrLn ("error msg from peer: " <> errstr)
          Right t@(Transit abilities' hints') -> do
            TIO.putStrLn "got a transit message as a response"
            TIO.putStrLn (show t)

            -- send file offer message
            fileSize <- getFileSize filepath
            let fileOffer = MagicWormhole.File (toS filepath) fileSize
            MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (encode fileOffer)))

            -- receive file ack message {"answer": {"file_ack": "ok"}}
            -- TODO: verify that file_ack is "ok"
            MagicWormhole.PlainText rxFileOffer <- atomically $ MagicWormhole.receiveMessage conn
            TIO.putStrLn (toS rxFileOffer)

            -- TODO: parse offer message from the peer

            -- we are now ready to prepare for the TCP communication
            -- TODO derive a transit key

            return ()
    )

--   -- * establish the tcp connection with the peer/relay
--   -- * send handshake message:
--   --     sender -> receiver: transit sender TXID_HEX ready\n\n
--   --     receiver -> sender: transit receiver RXID_HEX ready\n\n
--   -- * if sender is satisfied with the handshake, it sends
--   --     sender -> receiver: go\n
--   -- * TXID_HEX above is the HKDF(transit_key, 32, CTXinfo=b'transit_sender') for sender
--   --    and HKDF(transit_key, 32, CTXinfo=b'transit_receiver')
--   -- * TODO: relay handshake
--   -- * create record_keys (send_record_key and receive_record_key (secretboxes)
--   -- * send the file (40 byte chunks) over a direct connection to either the relay or peer.
--   -- * receiver, once it successfully received the file, sends "{ 'ack' : 'ok', 'sha256': HEXHEX }
  
  
-- receiveFile :: Session -> Passcode -> IO Status

