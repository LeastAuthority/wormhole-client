{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
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
commandParser = Opt.hsubparser (sendCommand <> receiveCommand)
  where
    sendCommand = Opt.command "send" (Opt.info sendOptions (Opt.progDesc "send a text message"))
    receiveCommand = Opt.command "receive" (Opt.info receiveOptions (Opt.progDesc "receive a text message"))
    receiveOptions :: Opt.Parser Command
    receiveOptions = pure Receive
    sendOptions :: Opt.Parser Command
    sendOptions = pure Send

opts :: Opt.ParserInfo Options
opts = Opt.info (Opt.helper <*> optionsParser) (Opt.fullDesc <> Opt.header "wormhole")

-- | genWordlist would produce a list of the form
--   [ ["01", "aardwark", "adroitness"],
--     ["02", "absurd", "adviser"],
--     ....
--     ["ff", "Zulu", "Yucatan"] ]
genWordList :: FilePath -> IO [[Text]]
genWordList wordlistFile = do
  file <- TIO.readFile wordlistFile
  let contents = map Text.words $ Text.lines file
  return contents

main :: IO ()
main = do
  options <- Opt.execParser opts
  wordList <- genWordList =<< getDataFileName "wordlist.txt"
  -- TIO.putStrLn $ show wordList
  side <- MagicWormhole.generateSide
  let endpoint = relayEndpoint options
  -- case cmd options of
  --   Send -> MagicWormhole.runClient endpoint appID side $ \session ->
  --     -- text, file or directory?
      
  return ()
