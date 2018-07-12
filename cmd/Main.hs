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

import Data.String (String)
import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified System.Console.Haskeline as H
import qualified System.Console.Haskeline.Completion as HC
import System.Random (randomR, getStdGen)
import qualified Options.Applicative as Opt

import qualified MagicWormhole

import Paths_hwormhole
import Helper
import Options
import FileTransfer
import TextMessages

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
  code <- H.runInputT (settings (genPasscodes ns wordList)) getInput
  return code
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
          sendText session (toS password) printSendHelpText msg
        TFileOrDir filename -> do
          -- file or dir
          password <- allocatePassword wordList
          sendFile session appID (toS password) printSendHelpText filename
          -- TIO.putStrLn "file or directory transfers not supported yet"
    Receive maybeCode -> MagicWormhole.runClient endpoint appID side $ \session ->
      case maybeCode of
        Nothing -> do -- get the code as a user input
          code <- getCode session wordList
          message <- receiveText session code
          putStr message
        Just code -> do
          -- if the sender is doing a file/dir transfer, it will send
          -- the transit first. (Unfortunate!)
          message <- receiveText session code
          putStr message
  return ()
    where
      appID = MagicWormhole.AppID "lothar.com/wormhole/text-or-file-xfer"
