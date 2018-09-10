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

import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified System.Console.Haskeline as H
import qualified System.Console.Haskeline.Completion as HC
import System.Random (randomR, getStdGen)
import qualified Crypto.Spake2 as Spake2

import Data.String (String)
import System.IO.Error (IOError)

import qualified MagicWormhole
import qualified Transit

import Paths_hwormhole
import Options

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

completeWord :: MonadIO m => [Text] -> HC.CompletionFunc m
completeWord wordlist = HC.completeWord Nothing "" completionFunc
  where
    completionFunc :: Monad m => String -> m [HC.Completion]
    completionFunc word = do
      let completions = filter (toS word `Text.isPrefixOf`) wordlist
      return $ map (HC.simpleCompletion . toS) completions

-- | Take an input code from the user with code completion.
-- In order for the code completion to work, we need to find
-- the possible open nameplates, the possible words and then
-- do the completion as the user types the code.
-- TODO: This function does too much. Perfect target for refactoring.
getCode :: MagicWormhole.Session -> [(Text, Text)] -> IO Text
getCode session wordList = do
  nameplates <- MagicWormhole.list session
  let ns = [ n | MagicWormhole.Nameplate n <- nameplates ]
  putText "Enter the receive wormhole code: "
  H.runInputT (settings (genPasscodes ns wordList)) getInput
  where
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

printSendHelpText :: Text -> IO ()
printSendHelpText passcode = do
  TIO.putStrLn $  "Wormhole code is: " <> passcode
  TIO.putStrLn "On the other computer, please run:"
  TIO.putStrLn ""
  TIO.putStrLn $ "wormhole receive " <> passcode

type Password = ByteString

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
send :: MagicWormhole.Session -> Transit.RelayEndpoint -> MagicWormhole.AppID -> Password -> Transit.MessageType -> IO (Either Transit.Error ())
send session transitserver appid password tfd = do
  -- first establish a wormhole session with the receiver and
  -- then talk the filetransfer protocol over it as follows.
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printSendHelpText $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn ->
        case tfd of
          Transit.TMsg msg -> do
            let offer = MagicWormhole.Message msg
            Transit.sendOffer conn offer
            -- wait for "answer" message with "message_ack" key
            Transit.liftEitherCommError <$> Transit.receiveMessageAck conn
          Transit.TFile filepath ->
            Transit.sendFile conn transitserver appid filepath
    )

-- | receive a text message or file from the wormhole peer.
receive :: MagicWormhole.Session -> Transit.RelayEndpoint -> MagicWormhole.AppID -> Text -> IO (Either Transit.Error ())
receive session transitserver appid code = do
  -- establish the connection
  let codeSplit = Text.split (=='-') code
  let (Just nameplate) = headMay codeSplit
  mailbox <- MagicWormhole.claim session (MagicWormhole.Nameplate nameplate)
  peer <- MagicWormhole.open session mailbox
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS (Text.strip code)))
    (\conn -> do
        -- unfortunately, the receiver has no idea which message to expect.
        -- If the sender is only sending a text message, it gets an offer first.
        -- if the sender is sending a file/directory, then transit comes first
        -- and then offer comes in. `Transit.receiveOffer' will attempt to interpret
        -- the bytestring as an offer message. If that fails, it passes the raw bytestring
        -- as a Left value so that we can try to decode it as a TransitMsg.
        someOffer <- Transit.receiveOffer conn
        case someOffer of
          Right (MagicWormhole.Message message) -> do
            TIO.putStrLn message
            result <- try (Transit.sendMessageAck conn "ok") :: IO (Either IOError ())
            return $ bimap (const (Transit.GeneralError (Transit.ConnectionError "sending the ack message failed"))) identity result
          Right (MagicWormhole.File _ _) -> do
            Transit.sendMessageAck conn "not_ok"
            return $ Left (Transit.GeneralError (Transit.ConnectionError "did not expect a file offer"))
          Right (MagicWormhole.Directory _ _ _ _ _) ->
            return $ Left (Transit.GeneralError (Transit.UnknownPeerMessage "directory offer is not supported"))
          -- ok, we received the Transit Message, send back a transit message
          Left received ->
            case (Transit.decodeTransitMsg (toS received)) of
              Left e -> return $ Left (Transit.GeneralError e)
              Right transitMsg ->
                Transit.receiveFile conn transitserver appid transitMsg
    )

main :: IO ()
main = do
  options <- commandlineParser
  wordList <- genWordList =<< getDataFileName "wordlist.txt"
  side <- MagicWormhole.generateSide
  let endpoint = relayEndpoint options
      transiturl = transitUrl options
  case cmd options of
    Send tfd -> MagicWormhole.runClient endpoint appID side $ \session -> do
      password <- allocatePassword wordList
      result <- send session transiturl appID (toS password) tfd
      either (TIO.putStrLn . show) return result
    Receive maybeCode -> MagicWormhole.runClient endpoint appID side $ \session -> do
      code <- getWormholeCode session wordList maybeCode
      result <- receive session transiturl appID code
      either (TIO.putStrLn . show) return result
    where
      appID = MagicWormhole.AppID "lothar.com/wormhole/text-or-file-xfer"
      getWormholeCode :: MagicWormhole.Session -> [(Text, Text)] -> Maybe Text -> IO Text
      getWormholeCode session wordList Nothing = getCode session wordList
      getWormholeCode _ _ (Just code) = return code
