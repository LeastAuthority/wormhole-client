{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
module Transit.Internal.Network
  (
    -- * build direct hints from port number and the interfaces on the host.
    buildDirectHints
    -- * parse and build transit relay hints
  , parseTransitRelayUri
  , buildRelayHints
  , RelayEndpoint(..)
    -- * low level bytestring buffer send/receive over a socket
  , sendBuffer
  , recvBuffer
    -- * TCP Endpoint
  , closeConnection
  , TCPEndpoint(..)
    -- * TCP Listener that listens on a random port, Server and Client
  , tcpListener
  , startServer
  , startClient
    -- * Error
  , CommunicationError(..)
  ) where

import Prelude (read)
import Protolude

import Transit.Internal.Messages (ConnectionHint(..), Hint(..), AbilityV1(..))

import Network.Socket
  ( addrSocketType
  , PortNumber
  , addrFlags
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
  , listen
  , accept
  , defaultHints
  , defaultPort
  , setSocketOption
  , SocketOption( ReuseAddr )
  , AddrInfoFlag ( AI_NUMERICSERV )
  , withSocketsDo
  )

import Network.Info
  ( getNetworkInterfaces
  , NetworkInterface(..)
  , IPv4(..)
  )

import Network.Socket.ByteString (send, recv)
import System.Timeout (timeout)
import Data.Text (splitOn)
import Data.String (String)

import qualified Data.Text.IO as TIO

tcpListener :: IO Socket
tcpListener = do
  let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
  addr:_ <- getAddrInfo (Just hints') (Just "0.0.0.0") (Just (show defaultPort))
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  setSocketOption sock' ReuseAddr 1
  bind sock' (addrAddress addr)
  listen sock' 5
  return sock'

type Hostname = Text

ipv4ToHostname :: Word32 -> Hostname
ipv4ToHostname ip =
  let (q1, r1) = ip `divMod` 256
      (q2, r2) = q1 `divMod` 256
      (q3, r3) = q2 `divMod` 256
  in
    show r1 <> "." <> show r2 <> "." <> show r3 <> "." <> show q3

buildDirectHints :: PortNumber -> IO [ConnectionHint]
buildDirectHints portnum = do
  nwInterfaces <- getNetworkInterfaces
  let nonLoopbackInterfaces =
        filter (\nwInterface ->
                   let (IPv4 addr4) = ipv4 nwInterface
                   in
                     (ipv4ToHostname addr4 /= "0.0.0.0")
                     && (ipv4ToHostname addr4 /= "127.0.0.1"))
        nwInterfaces
  return $ map (\nwInterface ->
                  let (IPv4 addr4) = ipv4 nwInterface in
                  Direct Hint { hostname = ipv4ToHostname addr4
                              , port = fromIntegral portnum
                              , priority = 0
                              , ctype = DirectTcpV1 }) nonLoopbackInterfaces

data RelayEndpoint
  = RelayEndpoint
  { relayhost :: Text
  , relayport :: Word16
  } deriving (Show, Eq)

parseTransitRelayUri :: String -> Maybe RelayEndpoint
parseTransitRelayUri url =
  let parts = splitOn ":" (toS @String @Text url)
      (Just host') = atMay parts 1
      (Just port') = atMay parts 2
  in
    if length parts == 3 && "tcp:" `isPrefixOf` url
    then Just (RelayEndpoint { relayhost = host', relayport = read @Word16 (toS port') })
    else Nothing

buildRelayHints :: RelayEndpoint -> [ConnectionHint]
buildRelayHints (RelayEndpoint host' port') =
  [Relay RelayV1 [Hint { hostname = host'
                       , port = port'
                       , priority = 0.0
                       , ctype = RelayV1 }]]

data TCPEndpoint
  = TCPEndpoint
    { sock :: Socket
    , conntype :: Maybe AbilityV1
    } deriving (Show, Eq)

tryToConnect :: AbilityV1 -> Hint -> IO (Maybe TCPEndpoint)
tryToConnect ability h@(Hint _ _ host portnum) =
  timeout 1000000 (bracketOnError
                    (init host portnum)
                    (\(sock', _) -> close sock')
                    (\(sock', addr) -> do
                        connect sock' $ addrAddress addr
                        return (TCPEndpoint sock' (Just ability))))
  where
    init host' port' = withSocketsDo $ do
      TIO.putStrLn $ "trying to connect to " <> (show h)
      addr <- resolve (toS host') (show port')
      sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      return (sock', addr)
    resolve host' port' = do
      let hints' = defaultHints { addrSocketType = Stream }
      addr:_ <- getAddrInfo (Just hints') (Just host') (Just port')
      return addr

sendBuffer :: TCPEndpoint -> ByteString -> IO Int
sendBuffer ep = send (sock ep)

recvBuffer :: TCPEndpoint -> Int -> IO ByteString
recvBuffer ep = recv (sock ep)

closeConnection :: TCPEndpoint -> IO ()
closeConnection ep = close (sock ep)

startServer :: Socket -> IO TCPEndpoint
startServer sock' = do
  (conn, _) <- accept sock'
  close sock'
  return (TCPEndpoint conn Nothing)

data CommunicationError
  = ConnectionError Text
  -- ^ We could not establish a socket connection.
  | OfferError Text
  -- ^ Clients could not exchange offer message.
  | TransitError Text
  -- ^ There was an error in transit protocol exchanges.
  | Sha256SumError Text
  -- ^ Sender got back a wrong sha256sum from the receiver.
  | UnknownPeerMessage Text
  -- ^ We could not identify the message from peer.
  deriving (Eq, Show)

instance Exception CommunicationError

startClient :: [ConnectionHint] -> IO TCPEndpoint
startClient hs = do
  let sortedHs = sort hs
      (dHs, rHs) = segregateHints sortedHs
  (ep1, ep2) <- concurrently
                (asum (map (tryToConnect DirectTcpV1) dHs))
                (asum (map (tryToConnect RelayV1) rHs))
  let maybeEndPoint = ep1 <|> ep2
  case maybeEndPoint of
    Just ep -> return ep
    Nothing -> throwIO (ConnectionError "Peer socket is not active")
  where
    -- (a -> b -> b) -> b -> [a] -> b
    segregateHints :: [ConnectionHint] -> ([Hint], [Hint])
    segregateHints = foldr go ([],[])
    go :: ConnectionHint -> ([Hint], [Hint]) -> ([Hint], [Hint])
    go hint (dhs, rhs) = case hint of
                           Direct h -> (h:dhs, rhs)
                           Relay _ hs' -> (dhs, hs' <> rhs)
