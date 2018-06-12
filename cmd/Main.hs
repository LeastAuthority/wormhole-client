{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Protolude

import qualified Options.Applicative as Opt
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO

import qualified MagicWormhole

import Paths_wormhole

data Options
  = Options
  { cmd :: Command
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  } deriving (Eq, Show)

data Command
  = Send
  | Receive
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
commandParser = Opt.hsubparser
  ( Opt.command "send" (Opt.info (pure Send) (Opt.progDesc "send a text message")) <>
    Opt.command "receive" (Opt.info (pure Receive) (Opt.progDesc "receive a text message")) )

opts :: Opt.ParserInfo Options
opts = Opt.info (Opt.helper <*> optionsParser) (Opt.fullDesc <> Opt.header "wormhole")

-- | genWordlist would produce a list of the form
--   [ ["aardwark", "adroitness"],
--     ["absurd", "adviser"],
--     ....
--     ["Zulu", "Yucatan"] ]
genWordList :: FilePath -> IO [[Text]]
genWordList wordlistFile = do
  file <- TIO.readFile wordlistFile
  let contents = map Text.words $ Text.lines file
  return contents

main :: IO ()
main = do
  options <- Opt.execParser opts
  wordList <- genWordList <$> getDataFileName "wordlist.txt"
  return ()
