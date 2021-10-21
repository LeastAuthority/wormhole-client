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

module Options
  ( commandlineParser
  )
where

import Protolude

import qualified Options.Applicative as Opt
import Data.String (String)

import qualified Transit

cmdlineParser :: Opt.Parser Transit.Cmdline
cmdlineParser
  = Transit.Cmdline
    <$> optionsParser
    <*> commandParser

commandParser :: Opt.Parser Transit.Command
commandParser = Opt.hsubparser (sendCommand <> receiveCommand)
  where
    sendCommand = Opt.command "send" (Opt.info sendOptions (Opt.progDesc "send a text message, a file or a directory"))
    receiveCommand = Opt.command "receive" (Opt.info receiveOptions (Opt.progDesc "receive a text message"))
    receiveOptions :: Opt.Parser Transit.Command
    receiveOptions = Transit.Receive <$> optional (Opt.strArgument (Opt.metavar "CODE")) <*> torOptParser
    sendOptions :: Opt.Parser Transit.Command
    sendOptions = Transit.Send <$> parseMessageType <*> torOptParser
    parseMessageType :: Opt.Parser Transit.MessageType
    parseMessageType = msgParser <|> fileOrDirParser
    msgParser :: Opt.Parser Transit.MessageType
    msgParser = Transit.TMsg <$> Opt.strOption (Opt.long "text" <> Opt.help "Text message to send")
    torOptParser :: Opt.Parser Bool
    torOptParser = Opt.switch (Opt.long "tor" <> Opt.help "use Tor when connecting")
    fileOrDirParser :: Opt.Parser Transit.MessageType
    fileOrDirParser = Transit.TFile <$> Opt.strArgument (Opt.metavar "FILENAME" <> Opt.help "file path")

optionsParser :: Opt.Parser Transit.Options
optionsParser
  = Transit.Options
  <$> Opt.option
    (Opt.maybeReader Transit.parseWebSocketEndpoint)
    ( Opt.long "relayserver-url" <>
      Opt.help "Endpoint for the Relay server" <>
      Opt.value defaultEndpoint <>
      Opt.showDefault )
    <*> Opt.option
    (Opt.maybeReader Transit.parseTransitRelayUri)
    ( Opt.long "transit-helper" <>
      Opt.help "Transit relay to use" <>
      Opt.value defaultTransitUrl <>
      Opt.showDefault )
    <*> Opt.option
    (Opt.maybeReader parseAppId)
    ( Opt.long "appid" <>
      Opt.help "appid to use" <>
      Opt.value defaultAppId <>
      Opt.showDefault )
    <*> Opt.switch
    ( Opt.long "verify" <>
      Opt.short 'v' <>
      Opt.help "display verification string and wait for approval")
  where
    -- | Default URL for relay server.
    --
    -- This is a relay server run by Brian Warner.
    defaultEndpoint = fromMaybe (panic "Invalid default URL") (Transit.parseWebSocketEndpoint "ws://relay.magic-wormhole.io:4000/v1")
    -- | Default Transit Relay Url
    --
    -- This is a Transit relay run by Brian Warner.
    defaultTransitUrl = fromMaybe (panic "Invalid transit relay URL") (Transit.parseTransitRelayUri "tcp:transit.magic-wormhole.io:4001")
    -- | Default App ID
    --
    -- This is the APPID for the `wormhole` file transfer application
    defaultAppId = Transit.AppID "lothar.com/wormhole/text-or-file-xfer"
    parseAppId :: String -> Maybe Transit.AppID
    parseAppId appid = Just (Transit.AppID (toS appid))

opts :: Opt.ParserInfo Transit.Cmdline
opts = Opt.info (Opt.helper <*> cmdlineParser) (Opt.fullDesc <> Opt.header "wormhole")

commandlineParser :: IO Transit.Cmdline
commandlineParser = Opt.execParser opts
