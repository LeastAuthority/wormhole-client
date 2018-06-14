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

module Main where

import Protolude

import qualified Crypto.Spake2 as Spake2
import qualified Data.Aeson as Aeson
import Data.String (String)
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as Opt
import qualified System.Console.Haskeline as H
import qualified System.Console.Haskeline.Completion as HC
import System.Random (randomR, getStdGen)

import qualified MagicWormhole

import Paths_wormhole

data Options
  = Options
  { cmd :: Command
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  } deriving (Eq, Show)

data Command
  = Send TransferType
  | Receive (Maybe Text)
  deriving (Eq, Show)

data TransferType
  = TMsg Text
  | TFileOrDir FilePath
  deriving (Show, Eq)

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
    sendOptions = Send <$> parseTransferType
    parseTransferType :: Opt.Parser TransferType
    parseTransferType = msgParser <|> fileOrDirParser
    msgParser :: Opt.Parser TransferType
    msgParser = TMsg <$> Opt.strOption (Opt.long "text" <> Opt.help "Text message to send")
    fileOrDirParser :: Opt.Parser TransferType
    fileOrDirParser = TFileOrDir <$> Opt.strArgument (Opt.metavar "FILENAME" <> Opt.help "file path")

opts :: Opt.ParserInfo Options
opts = Opt.info (Opt.helper <*> optionsParser) (Opt.fullDesc <> Opt.header "wormhole")

-- | genWordlist would produce a list of the form
--   [ ("aardwark", "adroitness"),
--     ("absurd", "adviser"),
--     ....
--     ("zulu", "yucatan") ]
genWordList :: FilePath -> IO [(Text, Text)]
genWordList wordlistFile = do
  file <- TIO.readFile wordlistFile
  let contents = map toWordPair $ Text.lines file
  return contents
    where
      toWordPair :: Text -> (Text, Text)
      toWordPair line =
        let ws = map Text.toLower $ Text.words line
            Just firstWord = atMay ws 1
            Just sndWord = atMay ws 2
        in (firstWord, sndWord)

genPasscodes :: [Text] -> [(Text, Text)] -> [Text]
genPasscodes nameplates wordpairs =
  let evens = map fst wordpairs
      odds = map snd wordpairs
      wordCombos = [ o <> "-" <> e | o <- odds, e <- evens ]
  in
    [ n <> "-" <> hiphenWord | n <- nameplates, hiphenWord <- wordCombos ]

allocatePassword :: [(Text, Text)] -> IO Text
allocatePassword wordlist = do
  g <- getStdGen
  let (r1, g') = randomR (0, 255) g
      (r2, _) = randomR (0, 255) g'
      Just evenW = fst <$> atMay wordlist r2
      Just oddW = snd <$> atMay wordlist r1
  return $ Text.concat [oddW, "-", evenW]

-- | A password used to exchange with a Magic Wormhole peer.
--
-- XXX: Just picking ByteString because that's the least amount of work. Need
-- to look up exact type of password in the magic-wormhole docs.
type Password = ByteString

printSendHelpText :: Text -> IO ()
printSendHelpText passcode = do
  TIO.putStrLn $  "Wormhole code is: " <> passcode
  TIO.putStrLn "On the other computer, please run:"
  TIO.putStrLn ""
  TIO.putStrLn $ "wormhole receive " <> passcode

-- | Send a text message to a Magic Wormhole peer.
sendText :: MagicWormhole.Session -> Password -> Text -> IO ()
sendText session password message = do
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printSendHelpText $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        let offer = MagicWormhole.Message message
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (Aeson.encode offer))))

completeWord :: MonadIO m => [Text] -> HC.CompletionFunc m
completeWord wordlist = HC.completeWord Nothing "" completionFunc
  where
    completionFunc :: Monad m => String -> m [HC.Completion]
    completionFunc word = do
      let completions = filter (toS word `Text.isPrefixOf`) wordlist
      return $ map (HC.simpleCompletion . toS) completions

-- | Receive a text message from a Magic Wormhole peer.
receiveText :: MagicWormhole.Session -> Text -> IO Text
receiveText session code = do
  let codeSplit = Text.split (=='-') code
  let (Just nameplate) = headMay codeSplit
  mailbox <- MagicWormhole.claim session (MagicWormhole.Nameplate nameplate)
  peer <- MagicWormhole.open session mailbox
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS (Text.strip code)))
    (\conn -> do
        MagicWormhole.PlainText received <- atomically $ MagicWormhole.receiveMessage conn
        case Aeson.eitherDecode (toS received) of
          Left err -> panic $ "Could not decode message: " <> show err
          Right (MagicWormhole.Message message) -> pure message)

main :: IO ()
main = do
  options <- Opt.execParser opts
  wordList <- genWordList =<< getDataFileName "wordlist.txt"
  side <- MagicWormhole.generateSide
  let endpoint = relayEndpoint options
  case cmd options of
    Send tfd -> MagicWormhole.runClient endpoint appID side $ \session ->
      case tfd of
        TMsg msg -> do
          -- text message
          password <- allocatePassword wordList
          sendText session (toS password) msg
        TFileOrDir filename ->
          TIO.putStrLn "file or directory transfers not supported yet"
    Receive maybeCode -> MagicWormhole.runClient endpoint appID side $ \session ->
      case maybeCode of
        Nothing -> do -- generate code
          nameplates <- MagicWormhole.list session
          let ns = [ n | MagicWormhole.Nameplate n <- nameplates ]
          putText "Enter the receive wormhole code: "
          code <- H.runInputT (settings (genPasscodes ns wordList)) getInput
          message <- receiveText session code
          putStr message
        Just code -> do
          message <- receiveText session code
          putStr message
  return ()
    where
      appID = MagicWormhole.AppID "lothar.com/wormhole/text-or-file-xfer"
      settings :: MonadIO m => [Text] -> H.Settings m
      settings possibleWords = H.Settings
        { H.complete = completeWord possibleWords
        , H.historyFile = Nothing
        , H.autoAddHistory = False
        }
      getInput :: H.InputT IO Text
      getInput = do
        minput <- H.getInputLine ""
        case minput of
          Nothing -> return ""
          Just input -> return (toS input)
