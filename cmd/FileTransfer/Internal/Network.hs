{-# LANGUAGE OverloadedStrings #-}
module FileTransfer.Internal.Network
  ( allocateTcpPort
  , buildDirectHints
  , runTransitProtocol
  , sendBuffer
  , recvBuffer
  , TCPEndpoint
  ) where

import Protolude

import FileTransfer.Internal.Protocol

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
  , Socket(..)
  , connect
  , bind
  , defaultHints
  , defaultPort
  , setSocketOption
  , SocketOption( ReuseAddr )
  , AddrInfoFlag ( AI_NUMERICSERV )
  , PortNumber( PortNum )
  , withSocketsDo
  )
import Network
  ( PortID(..)
  )

import Network.Info
  ( getNetworkInterfaces
  , NetworkInterface(..)
  , IPv4(..)
  )
import Network.Socket.ByteString
  ( send
  , recv
  )
import System.Timeout
  ( timeout
  )
import qualified Control.Exception as E
import qualified Data.Text.IO as TIO


allocateTcpPort :: IO PortNumber
allocateTcpPort = E.bracket setup close socketPort
  where setup = do
          let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
          addr:_ <- getAddrInfo (Just hints') (Just "127.0.0.1") (Just (show defaultPort))
          sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
          _ <- setSocketOption sock' ReuseAddr 1
          _ <- bind sock' (addrAddress addr)
          return sock'

type Hostname = Text

ipv4ToHostname :: Word32 -> Hostname
ipv4ToHostname ip =
  let (q1, r1) = ip `divMod` 256
      (q2, r2) = q1 `divMod` 256
      (q3, r3) = q2 `divMod` 256
  in
    show r1 <> "." <> show r2 <> "." <> show r3 <> "." <> show q3

buildDirectHints :: IO [ConnectionHint]
buildDirectHints = do
  (PortNum portnum) <- allocateTcpPort
  nwInterfaces <- getNetworkInterfaces
  let nonLoopbackInterfaces =
        filter (\nwInterface -> let (IPv4 addr4) = ipv4 nwInterface in addr4 /= 0x0100007f) nwInterfaces
  return $ map (\nwInterface ->
                  let (IPv4 addr4) = ipv4 nwInterface in
                  Direct Hint { hostname = ipv4ToHostname addr4
                              , port = portnum
                              , priority = 0
                              , ctype = DirectTcpV1 }) nonLoopbackInterfaces


data TCPEndpoint
  = TCPEndpoint
  { chint :: ConnectionHint
  , ability :: Ability
  , sock :: Socket
  } deriving (Show, Eq)

tryToConnect :: Ability -> ConnectionHint -> IO (Maybe TCPEndpoint)
tryToConnect a@(Ability DirectTcpV1) h@(Direct (Hint DirectTcpV1 _ host portnum)) =
  withSocketsDo $ do
  addr <- resolve (toS host) (show portnum)
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  timeout 10000000 (do
                       connect sock' $ addrAddress addr
                       return $ TCPEndpoint h a sock')
  where
    resolve host' port' = do
      let hints' = defaultHints { addrSocketType = Stream }
      addr:_ <- getAddrInfo (Just hints') (Just host') (Just port')
      return addr
tryToConnect (Ability DirectTcpV1) _ = do
  TIO.putStrLn "Tor hints and Relays are not supported yet"
  return Nothing
tryToConnect (Ability RelayV1) _ = do
  TIO.putStrLn "Relays are not supported yet"
  return Nothing

sendBuffer :: TCPEndpoint -> ByteString -> IO Int
sendBuffer ep = send (sock ep)

recvBuffer :: TCPEndpoint -> Int -> IO ByteString
recvBuffer ep = recv (sock ep)

runTransitProtocol :: [Ability] -> [ConnectionHint] -> (TCPEndpoint -> IO ()) -> IO ()
runTransitProtocol as hs app = do
  -- establish the tcp connection with the peer/relay
  -- for each (hostname, port) pair in direct hints, try to establish connection
  maybeEndPoint <- asum (map (\hint -> case hint of
                                         Direct _ ->
                                           tryToConnect (Ability DirectTcpV1) hint
                                         _ -> return Nothing
                             ) hs)
  case maybeEndPoint of
    Just ep -> app ep
    Nothing -> return ()

-- receiveFile :: Session -> Passcode -> IO Status
