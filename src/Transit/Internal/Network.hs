-- | Description: functions that deal with the network i/o
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
module Transit.Internal.Network
  (
    -- * build hints (direct and relay) from relay url, port number and the network interfaces.
    buildHints
  , buildRelayHints
    -- * parse and build transit relay hints
  , parseTransitRelayUri
  , RelayEndpoint(..)
    -- * low level bytestring buffer send/receive over a socket
  , sendBuffer
  , recvBuffer
    -- * TCP Endpoint
  , closeConnection
  , TCPEndpoint(..)
  , TransitEndpoint(..)
    -- * TCP Listener that listens on a random port, Server and Client
  , tcpListener
  , getSocketPort
  , startServer
  , startClient
  , connectToTor
    -- * Errors
  , CommunicationError(..)
  ) where

import Prelude (read)
import Protolude hiding (toS)
import Protolude.Conv (toS)

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
  , socketPort
  , Socket
  , SockAddr (SockAddrInet)
  , connect
  , bind
  , listen
  , accept
  , defaultHints
  , defaultPort
  , setSocketOption
  , SocketOption( ReuseAddr )
  , AddrInfoFlag ( AI_NUMERICHOST )
  , withSocketsDo
  , tupleToHostAddress
  )

import Network.Info
  ( getNetworkInterfaces
  , NetworkInterface(..)
  , IPv4(..)
  )

import Network.Socket.ByteString (send, recv)
import System.Timeout (timeout)
import Control.Concurrent.Async (mapConcurrently)
import Data.Text (splitOn)
import Data.String (String)
import System.IO.Error (IOError)
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Network.Socks5 as Socks
import MagicWormhole (WebSocketEndpoint(..))

import qualified Data.Text.IO as TIO
import qualified Data.Set as Set

-- | Type representing the network protocol errors
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

-- | Listen on all the interfaces on a randomly assigned default port
tcpListener :: Bool -> IO (Maybe Socket)
tcpListener True = return Nothing
tcpListener False = do
  let hints' = defaultHints { addrFlags = [AI_NUMERICHOST], addrSocketType = Stream }
  addr:_ <- getAddrInfo (Just hints') (Just "0.0.0.0") (Just (show defaultPort))
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  setSocketOption sock' ReuseAddr 1
  bind sock' (addrAddress addr)
  listen sock' 5
  return (Just sock')

getSocketPort :: Maybe Socket -> IO (Maybe PortNumber)
getSocketPort Nothing     = return Nothing
getSocketPort (Just sock') = do
  portnum <- socketPort sock'
  return (Just portnum)

type Hostname = Text

ipv4ToHostname :: Word32 -> Hostname
ipv4ToHostname ip =
  let (q1, r1) = ip `divMod` 256
      (q2, r2) = q1 `divMod` 256
      (q3, r3) = q2 `divMod` 256
  in
    show r1 <> "." <> show r2 <> "." <> show r3 <> "." <> show q3

buildDirectHints :: PortNumber -> IO (Set.Set ConnectionHint)
buildDirectHints portnum = do
  nwInterfaces <- getNetworkInterfaces
  let nonLoopbackInterfaces =
        filter (\nwInterface ->
                   let (IPv4 addr4) = ipv4 nwInterface
                   in
                     (ipv4ToHostname addr4 /= "0.0.0.0")
                     && (ipv4ToHostname addr4 /= "127.0.0.1"))
        nwInterfaces
  return $ Set.fromList $ map (\nwInterface ->
                                 let (IPv4 addr4) = ipv4 nwInterface in
                                   Direct Hint { hostname = ipv4ToHostname addr4
                                               , port = fromIntegral portnum
                                               , priority = 0
                                               , ctype = DirectTcpV1 }) nonLoopbackInterfaces

-- | Type representing a Relay Endpoint URL
data RelayEndpoint
  = RelayEndpoint
  { relayhost :: Text
  , relayport :: Word16
  } deriving (Show, Eq)

-- | Parse transit url of the form /tcp:hostname:port/
parseTransitRelayUri :: String -> Maybe RelayEndpoint
parseTransitRelayUri url =
  let parts = splitOn ":" (toS @String @Text url)
      (Just host') = atMay parts 1
      (Just port') = atMay parts 2
  in
    if length parts == 3 && "tcp:" `isPrefixOf` url
    then Just (RelayEndpoint { relayhost = host', relayport = read @Word16 (toS port') })
    else Nothing

-- | The client at the sending side and receiving side may be
-- invoked with different relay hint urls. These get exchanged
-- in the transit message. After successfully receiving the transit
-- message, each client should combine the hints of the peer along
-- with its relay hints to get the full set of hints.
buildRelayHints :: RelayEndpoint -> Set.Set ConnectionHint
buildRelayHints (RelayEndpoint host' port') =
  Set.singleton $ Relay RelayV1 [Hint { hostname = host'
                                      , port = port'
                                      , priority = 0.0
                                      , ctype = DirectTcpV1 }]

-- | Build a client's connection hint
buildHints :: Maybe PortNumber -> RelayEndpoint -> IO (Set.Set ConnectionHint)
buildHints Nothing relayEndpoint = return (buildRelayHints relayEndpoint)
buildHints (Just portnum) relayEndpoint = do
  directHints <- buildDirectHints portnum
  let relayHints = buildRelayHints relayEndpoint
  return (directHints <> relayHints)

-- | A type representing the connected TCP endpoint
data TCPEndpoint
  = TCPEndpoint
    { sock :: Socket
    , conntype :: Maybe AbilityV1
    } deriving (Show, Eq)

-- | A type representing an "authenticated" TCP endpoint
data TransitEndpoint
  = TransitEndpoint
    { peerEndpoint :: TCPEndpoint
    , senderKey :: SecretBox.Key
    , receiverKey :: SecretBox.Key
    } deriving (Eq)


tryToConnect :: AbilityV1 -> Hint -> IO (Maybe TCPEndpoint)
tryToConnect ability (Hint _ _ host portnum) =
  timeout 1000000 (bracketOnError
                    (init host portnum)
                    (\(sock', _) -> close sock')
                    (\(sock', addr) -> do
                        connect sock' $ addrAddress addr
                        return (TCPEndpoint sock' (Just ability))))
  where
    init host' port' = withSocketsDo $ do
      addr <- resolve (toS host') (show port')
      sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      return (sock', addr)
    resolve host' port' = do
      let hints' = defaultHints { addrSocketType = Stream }
      addr:_ <- getAddrInfo (Just hints') (Just host') (Just port')
      return addr

-- | Low level function to send a fixed length bytestring to
-- the peer represented by /ep/.
sendBuffer :: TCPEndpoint -> ByteString -> IO Int
sendBuffer ep = send (sock ep)

-- | Low level function to receive a byte buffer of specified
-- length from the peer represented by /ep/.
recvBuffer :: TCPEndpoint -> Int -> IO ByteString
recvBuffer ep = recv (sock ep)

-- | Close the peer network connection.
closeConnection :: TransitEndpoint -> IO ()
closeConnection ep = close (sock (peerEndpoint ep))

-- | Accept and return the TCP Endpoint representing the peer
startServer :: Socket -> IO (Either CommunicationError TCPEndpoint)
startServer sock' = do
  res <- try $ accept sock' :: IO (Either IOError (Socket, SockAddr))
  close sock'
  return $ bimap (const (ConnectionError "accept: IO error")) (\(conn, _) -> (TCPEndpoint conn Nothing)) res

-- | Try to concurrently connect to the given list of connection hints and
-- return the first peer that succeeds.
startClient :: [ConnectionHint] -> IO (Either CommunicationError TCPEndpoint)
startClient hs = do
  let sortedHs = sort hs
      (dHs, rHs) = segregateHints sortedHs
  maybeEndPoint <- do
    (ep1s, ep2s) <- concurrently
                    (mapConcurrently (tryToConnect DirectTcpV1) dHs)
                    (mapConcurrently (tryToConnect RelayV1) rHs)
    let ep1 = asum ep1s
        ep2 = asum ep2s
    return $ ep1 <|> ep2
  case maybeEndPoint of
    Just ep -> return (Right ep)
    Nothing -> return (Left (ConnectionError "Peer socket is not active"))
  where
    -- (a -> b -> b) -> b -> [a] -> b
    segregateHints :: [ConnectionHint] -> ([Hint], [Hint])
    segregateHints = foldr go ([],[])
    go :: ConnectionHint -> ([Hint], [Hint]) -> ([Hint], [Hint])
    go hint (dhs, rhs) = case hint of
                           Direct h -> (h:dhs, rhs)
                           Relay _ hs' -> (dhs, hs' <> rhs)

torPort :: PortNumber
torPort = 9050

tbbPort :: PortNumber
tbbPort = 9150

-- | connect to a tor socks proxy
connectToTor :: WebSocketEndpoint -> IO (Either CommunicationError Socket)
connectToTor endpoint = do
  TIO.putStrLn "attempting to connect via Tor ..."
  let torSockConf = Socks.defaultSocksConf (SockAddrInet torPort (tupleToHostAddress (127, 0, 0, 1)))
      tbbSockConf = Socks.defaultSocksConf (SockAddrInet tbbPort (tupleToHostAddress (127, 0, 0, 1)))
  res <- try $ Socks.socksConnect torSockConf (remote endpoint) <|>
         Socks.socksConnect tbbSockConf (remote endpoint) :: IO (Either IOError (Socket, (Socks.SocksHostAddress, PortNumber)))
  return $ bimap (const (ConnectionError "cannot connect to tor: check whether tor daemon or tor browser is running.")) fst res
  where
    remote ep =
      let (WebSocketEndpoint hostname' port' _) = ep in
        Socks.SocksAddress (Socks.SocksAddrDomainName (toS hostname')) (fromIntegral port')
