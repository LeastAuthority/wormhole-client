{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main where

import Protolude

import qualified Crypto.Spake2 as Spake2
import qualified Data.Aeson as Aeson
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified Options.Applicative as Opt
import qualified System.Posix.Files as Unix
import System.Random (randomR, getStdGen)

import qualified MagicWormhole

import Paths_wormhole

data Options
  = Options
  { cmd :: Command
  , relayEndpoint :: MagicWormhole.WebSocketEndpoint
  } deriving (Eq, Show)

data Command
  = Send Text
  | Receive
  deriving (Eq, Show)

data TransferType
  = Message Text
  | File FilePath
  | Directory FilePath
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
    receiveOptions = pure Receive
    sendOptions :: Opt.Parser Command
    sendOptions = Send <$> Opt.strArgument (Opt.metavar "TEXT-OR-FILE-OR-DIR" <> Opt.help "text message or a file or directory path")

opts :: Opt.ParserInfo Options
opts = Opt.info (Opt.helper <*> optionsParser) (Opt.fullDesc <> Opt.header "wormhole")

-- | genWordlist would produce a list of the form
--   [ ["01", "aardwark", "adroitness"],
--     ["02", "absurd", "adviser"],
--     ....
--     ["ff", "Zulu", "Yucatan"] ]
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

allocatePassword :: [(Text, Text)] -> IO Text
allocatePassword wordlist = do
  g <- getStdGen
  let (r1, g') = randomR (0, 255) g
      (r2, _) = randomR (0, 255) g'
      Just odd = atMay wordlist r1 >>= Just . fst
      Just even = atMay wordlist r2 >>= Just . snd
  return $ Text.concat [odd, "-", even]

-- | A password used to exchange with a Magic Wormhole peer.
--
-- XXX: Just picking ByteString because that's the least amount of work. Need
-- to look up exact type of password in the magic-wormhole docs.
type Password = ByteString

-- | Send a text message to a Magic Wormhole peer.
sendText :: MagicWormhole.Session -> Password -> Text -> IO ()
sendText session password message = do
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  TIO.putStrLn $ "at the receiving side, please type: " <> toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn -> do
        let offer = MagicWormhole.Message message
        MagicWormhole.sendMessage conn (MagicWormhole.PlainText (toS (Aeson.encode offer))))

main :: IO ()
main = do
  options <- Opt.execParser opts
  wordList <- genWordList =<< getDataFileName "wordlist.txt"
  side <- MagicWormhole.generateSide
  let endpoint = relayEndpoint options
  case cmd options of
    Send tfd -> MagicWormhole.runClient endpoint appID side $ \session ->
      -- text, file or directory?
      -- status <- Unix.getFileStatus (toS tfd)
      let isDir = False -- Unix.isDirectory status
          isFile = False -- Unix.isRegularFile status
        in
        if not isDir && not isFile
        then do
          -- text message
          password <- allocatePassword wordList
          sendText session (toS password) tfd
        else
          TIO.putStrLn "file or directory transfers not supported yet"
    _ -> TIO.putStrLn "unsupported command"
  return ()
    where appID = MagicWormhole.AppID "lothar.com/wormhole/text-or-file-xfer"
