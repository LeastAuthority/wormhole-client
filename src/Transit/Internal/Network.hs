{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Transit.Internal.Network
  ( allocateTcpPort
  , buildDirectHints
  , runTransitProtocol
  , sendBuffer
  , recvBuffer
  , closeConnection
  , TCPEndpoint
  , PortNumber
  , startServer
  ) where

import Protolude

import Transit.Internal.Messages

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
allocateTcpPort = E.bracket start close socketPort
  where start = do
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


data TCPEndpoint
  = TCPEndpoint
    { sock :: Socket
    } deriving (Show, Eq)

tryToConnect :: Ability -> ConnectionHint -> IO (Maybe TCPEndpoint)
tryToConnect a@(Ability DirectTcpV1) h@(Direct (Hint DirectTcpV1 _ host portnum)) =
  withSocketsDo $ do
  addr <- resolve (toS host) (show portnum)
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  timeout 10000000 (do
                       testAddress sock' $ addrAddress addr
                       -- return $ TCPEndpoint h a sock'
                       return $ TCPEndpoint sock')
  where
    resolve host' port' = do
      let hints' = defaultHints { addrSocketType = Stream }
      addr:_ <- getAddrInfo (Just hints') (Just host') (Just port')
      return addr
--    testAddress :: Socket -> SockAddr -> IO ()
    testAddress sock addr = do
      result <- try $ connect sock addr
      case result of
        Left (e :: E.SomeException) -> return ()
        Right h -> return ()
tryToConnect (Ability DirectTcpV1) _ = do
  TIO.putStrLn "Tor hints and Relays are not supported yet"
  return Nothing
tryToConnect (Ability RelayV1) _ = do
  TIO.putStrLn "Relays are not supported yet"
  return Nothing

sendBuffer :: TCPEndpoint -> ByteString -> IO (Either IOException Int)
sendBuffer ep = try . send (sock ep)

recvBuffer :: TCPEndpoint -> Int -> IO (Either IOException ByteString)
recvBuffer ep = try . recv (sock ep)

closeConnection :: TCPEndpoint -> IO ()
closeConnection ep = do
  close (sock ep)

startServer :: PortNumber -> IO TCPEndpoint
startServer port = do
  let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
  addr:_ <- getAddrInfo (Just hints') (Just "0.0.0.0") (Just (show port))
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  _ <- setSocketOption sock' ReuseAddr 1
  _ <- bind sock' (addrAddress addr)
  port <- socketPort sock'
  listen sock' 5
  (sock'', peer) <- accept sock'
  return (TCPEndpoint sock'')

data ConnectionError
  = ConnectionError Text
  deriving (Eq, Show)

instance Exception ConnectionError

runTransitProtocol :: [Ability] -> [ConnectionHint] -> Async TCPEndpoint -> (TCPEndpoint -> IO ()) -> IO ()
runTransitProtocol as hs serverAsync app = do
  -- establish the tcp connection with the peer/relay
  -- for each (hostname, port) pair in direct hints, try to establish connection
  maybeServerAccepted <- poll serverAsync
  case maybeServerAccepted of
    Nothing -> do
      maybeClientEndPoint <- asum (map (tryToConnect (Ability DirectTcpV1)) hs)
      case maybeClientEndPoint of
        Just ep -> do
          -- kill server async
          cancel serverAsync
          app ep
        Nothing -> throwIO (ConnectionError "Peer socket is not active")
    Just (Right ep) -> app ep
    Just e -> panic (show e)
