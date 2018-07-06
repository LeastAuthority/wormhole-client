{-# LANGUAGE OverloadedStrings #-}
module FileTransfer.Internal.Network
  ( allocateTcpPort
  , runTransitProtocol
  ) where

import Protolude

import FileTransfer.Internal.Protocol
import FileTransfer.Internal.Messages

import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import Network.Socket
  ( addrSocketType
  , PortNumber
  , addrFlags
  , socketPort
  , addrAddress
  , addrProtocol
  , addrFamily
  , getAddrInfo
  , SocketType ( Stream )
  , close
  , socket
  , bind
  , defaultHints
  , defaultPort
  , setSocketOption
  , SocketOption( ReuseAddr )
  , AddrInfoFlag ( AI_NUMERICSERV )
  , PortNumber( PortNum )
  )
import Network
  ( connectTo
  , PortID(..)
  )
import Network.Info
  ( getNetworkInterfaces
  , NetworkInterface(..)
  , IPv4(..)
  )

import qualified Control.Exception as E
import qualified Crypto.Saltine.Class as Saltine
import qualified Data.Text.IO as TIO

import qualified MagicWormhole

allocateTcpPort :: IO PortNumber
allocateTcpPort = E.bracket setup close socketPort
  where setup = do
          let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
          addr:_ <- getAddrInfo (Just hints') (Just "127.0.0.1") (Just (show defaultPort))
          sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
          _ <- setSocketOption sock ReuseAddr 1
          _ <- bind sock (addrAddress addr)
          return sock

type Hostname = Text

ipv4ToHostName :: Word32 -> Hostname
ipv4ToHostName ip =
  let (q1, r1) = ip `divMod` 256
      (q2, r2) = q1 `divMod` 256
      (q3, r3) = q2 `divMod` 256
  in
    (show q3) <> "." <> (show r3) <> "." <> (show r2) <> "." <> (show r1)

buildDirectHints :: IO [ConnectionHint]
buildDirectHints = do
  (PortNum portnum) <- allocateTcpPort
  nwInterfaces <- getNetworkInterfaces
  let nonLoopbackInterfaces =
        filter (\nwInterface -> let (IPv4 addr4) = ipv4 nwInterface in addr4 /= 0x0100007f) nwInterfaces
  return $ map (\nwInterface ->
                  let (IPv4 addr4) = ipv4 nwInterface in
                  Direct (Hint { hostname = ipv4ToHostName addr4
                               , port = portnum
                               , priority = 0
                               , ctype = DirectTcpV1 })) nonLoopbackInterfaces


data TCPEndpoint
  = TCPEndpoint
  { hint :: ConnectionHint
  , ability :: Ability
  , handle :: Handle
  }

tryToConnect :: Ability -> ConnectionHint -> IO (Maybe TCPEndpoint)
tryToConnect a@(Ability DirectTcpV1) h@(Direct (Hint DirectTcpV1 _ hostname portnum)) = do
  let port = PortNumber (fromIntegral portnum)
  handle <- try (connectTo (toS hostname) port)
  case handle of
    Left (SomeException e) -> return Nothing
    Right handle' -> return $ Just (TCPEndpoint h a handle')

runTransitProtocol :: SecretBox.Key -> [Ability] -> [ConnectionHint] -> (TCPEndpoint -> IO a) -> IO ()
runTransitProtocol key as hs app = do
  -- * establish the tcp connection with the peer/relay
  --  for each (hostname, port) pair in direct hints, try to establish
  --  a connection.
  let sHandshakeMsg = makeSenderHandshake (MagicWormhole.SessionKey (Saltine.encode key))
  TIO.putStrLn (toS sHandshakeMsg)

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
