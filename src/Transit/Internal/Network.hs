{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
module Transit.Internal.Network
  ( allocateTcpPort
  , buildDirectHints
  , sendBuffer
  , recvBuffer
  , closeConnection
  , TCPEndpoint(..)
  , PortNumber
  , startServer
  , startClient
  , CommunicationError(..)
  ) where

import Protolude

import Transit.Internal.Messages (ConnectionHint(..), Hint(..), AbilityV1(..), Ability(..))

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
tryToConnect (Ability DirectTcpV1) (Direct (Hint DirectTcpV1 _ host portnum)) =
  withSocketsDo $ do
  addr <- resolve (toS host) (show portnum)
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  timeout 10000000 (testAddress sock' $ addrAddress addr)
  where
    resolve host' port' = do
      let hints' = defaultHints { addrSocketType = Stream }
      addr:_ <- getAddrInfo (Just hints') (Just host') (Just port')
      return addr
    testAddress so addr = do
      result <- try $ connect so addr
      case result of
        Left (e :: E.SomeException) -> throwIO e
        Right _ -> return (TCPEndpoint so)
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

closeConnection :: TCPEndpoint -> IO ()
closeConnection ep = close (sock ep)

startServer :: PortNumber -> IO TCPEndpoint
startServer portnum = do
  let hints' = defaultHints { addrFlags = [AI_NUMERICSERV], addrSocketType = Stream }
  addr:_ <- getAddrInfo (Just hints') (Just "0.0.0.0") (Just (show portnum))
  sock' <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  _ <- setSocketOption sock' ReuseAddr 1
  _ <- bind sock' (addrAddress addr)
  listen sock' 5
  (conn, _) <- accept sock'
  close sock'
  return (TCPEndpoint conn)

data CommunicationError
  = ConnectionError Text
  | OfferError Text
  | TransitError Text
  | Sha256SumError Text
  | UnknownPeerMessage Text
  deriving (Eq, Show)

instance Exception CommunicationError

startClient :: [Ability] -> [ConnectionHint] -> IO TCPEndpoint
startClient as hs = do
  maybeClientEndPoint <- asum (map (tryToConnect (Ability DirectTcpV1)) hs)
  case maybeClientEndPoint of
    Just ep -> return ep
    Nothing -> throwIO (ConnectionError "Peer socket is not active")
