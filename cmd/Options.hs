-- This file is part of hwormhole.

-- hwormhole is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- hwormhole is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with hwormhole.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Options where

import Protolude

import qualified Options.Applicative as Opt

import qualified MagicWormhole
import Transit

data Options
  = Options
  { cmd :: Command
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  } deriving (Eq, Show)

data Command
  = Send MessageType
  | Receive (Maybe Text)
  deriving (Eq, Show)

optionsParser :: Opt.Parser Options
optionsParser
  = Options
    <$> commandParser
    <*> Opt.option
    (Opt.maybeReader MagicWormhole.parseWebSocketEndpoint)
    ( Opt.long "relayserver-url" <>
      Opt.help "Endpoint for the Relay server" <>
      Opt.value defaultEndpoint <>
      Opt.showDefault )
  where
    -- | Default URL for relay server.
    --
    -- This is a relay server run by Brian Warner.
    defaultEndpoint = fromMaybe (panic "Invalid default URL") (MagicWormhole.parseWebSocketEndpoint "ws://relay.magic-wormhole.io:4000/v1")

commandParser :: Opt.Parser Command
commandParser = Opt.hsubparser (sendCommand <> receiveCommand)
  where
    sendCommand = Opt.command "send" (Opt.info sendOptions (Opt.progDesc "send a text message, a file or a directory"))
    receiveCommand = Opt.command "receive" (Opt.info receiveOptions (Opt.progDesc "receive a text message"))
    receiveOptions :: Opt.Parser Command
    receiveOptions = Receive <$> optional (Opt.strArgument (Opt.metavar "CODE"))
    sendOptions :: Opt.Parser Command
    sendOptions = Send <$> parseMessageType
    parseMessageType :: Opt.Parser MessageType
    parseMessageType = msgParser <|> fileOrDirParser
    msgParser :: Opt.Parser MessageType
    msgParser = TMsg <$> Opt.strOption (Opt.long "text" <> Opt.help "Text message to send")
    fileOrDirParser :: Opt.Parser MessageType
    fileOrDirParser = TFile <$> Opt.strArgument (Opt.metavar "FILENAME" <> Opt.help "file path")

opts :: Opt.ParserInfo Options
opts = Opt.info (Opt.helper <*> optionsParser) (Opt.fullDesc <> Opt.header "wormhole")
