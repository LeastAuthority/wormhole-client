{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Transit.Internal.App
  ( Env(..)
  , prepareAppEnv
  , app
  )
where

import Protolude

import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified MagicWormhole
import qualified System.Console.Haskeline as H
import qualified System.Console.Haskeline.Completion as HC
import qualified Crypto.Spake2 as Spake2

import System.IO.Error (IOError)
import System.Random (randomR, getStdGen)
import Data.String (String)
import Control.Monad.Trans.Except (ExceptT(..))

import Transit.Internal.Conf (Options(..), Command(..))
import Transit.Internal.Errors (Error(..), liftEitherCommError, CommunicationError(..))
import Transit.Internal.FileTransfer(MessageType(..), sendFile, receiveFile)
import Transit.Internal.Peer (sendOffer, receiveOffer, receiveMessageAck, sendMessageAck, decodeTransitMsg)
import Paths_hwormhole

type Password = ByteString

data Env
  = Env { appID :: MagicWormhole.AppID
        , side :: MagicWormhole.Side
        , config :: Options
        , wordList :: [(Text, Text)]
        }

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

prepareAppEnv :: Text -> FilePath -> Options -> IO Env
prepareAppEnv appid wordlistPath options = do
  side' <- MagicWormhole.generateSide
  wordlist <- genWordList =<< getDataFileName wordlistPath
  let appID' = MagicWormhole.AppID appid
  return $ Env appID' side' options wordlist

allocatePassword :: [(Text, Text)] -> IO Text
allocatePassword wordlist = do
  g <- getStdGen
  let (r1, g') = randomR (0, 255) g
      (r2, _) = randomR (0, 255) g'
      Just evenW = fst <$> atMay wordlist r2
      Just oddW = snd <$> atMay wordlist r1
  return $ Text.concat [oddW, "-", evenW]

-- | Given the magic-wormhole session, appid, password, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
send :: Env -> MagicWormhole.Session -> Password -> MessageType -> IO (Either Error ())
send env session password tfd = do
  -- first establish a wormhole session with the receiver and
  -- then talk the filetransfer protocol over it as follows.
  let options = config env
  let appid = appID env
  let transitserver = transitUrl options
  nameplate <- MagicWormhole.allocate session
  mailbox <- MagicWormhole.claim session nameplate
  peer <- MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  printSendHelpText $ toS n <> "-" <> toS password
  MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS n <> "-" <> password))
    (\conn ->
        case tfd of
          TMsg msg -> do
            let offer = MagicWormhole.Message msg
            sendOffer conn offer
            -- wait for "answer" message with "message_ack" key
            liftEitherCommError <$> receiveMessageAck conn
          TFile filepath ->
            sendFile conn transitserver appid filepath
    )

-- | receive a text message or file from the wormhole peer.
receive :: Env -> MagicWormhole.Session -> Text -> IO (Either Error ())
receive env session code = do
  -- establish the connection
  let options = config env
  let appid = appID env
  let transitserver = transitUrl options
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
        someOffer <- receiveOffer conn
        case someOffer of
          Right (MagicWormhole.Message message) -> do
            TIO.putStrLn message
            result <- try (sendMessageAck conn "ok") :: IO (Either IOError ())
            return $ bimap (const (GeneralError (ConnectionError "sending the ack message failed"))) identity result
          Right (MagicWormhole.File _ _) -> do
            sendMessageAck conn "not_ok"
            return $ Left (GeneralError (ConnectionError "did not expect a file offer"))
          Right (MagicWormhole.Directory _ _ _ _ _) ->
            return $ Left (GeneralError (UnknownPeerMessage "directory offer is not supported"))
          -- ok, we received the Transit Message, send back a transit message
          Left received ->
            case (decodeTransitMsg (toS received)) of
              Left e -> return $ Left (GeneralError e)
              Right transitMsg ->
                receiveFile conn transitserver appid transitMsg
    )

genPasscodes :: [Text] -> [(Text, Text)] -> [Text]
genPasscodes nameplates wordpairs =
  let evens = map fst wordpairs
      odds = map snd wordpairs
      wordCombos = [ o <> "-" <> e | o <- odds, e <- evens ]
  in
    [ n <> "-" <> hiphenWord | n <- nameplates, hiphenWord <- wordCombos ]

printSendHelpText :: Text -> IO ()
printSendHelpText passcode = do
  TIO.putStrLn $  "Wormhole code is: " <> passcode
  TIO.putStrLn "On the other computer, please run:"
  TIO.putStrLn ""
  TIO.putStrLn $ "wormhole receive " <> passcode

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
getCode session wordlist = do
  nameplates <- MagicWormhole.list session
  let ns = [ n | MagicWormhole.Nameplate n <- nameplates ]
  putText "Enter the receive wormhole code: "
  H.runInputT (settings (genPasscodes ns wordlist)) getInput
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

newtype App a = App {
  runApp :: ReaderT Env (ExceptT Error IO) a
  } deriving (Functor, Applicative, Monad, MonadIO, MonadReader Env, MonadError Error)

app :: Env -> ExceptT Error IO ()
app env = do
  let options = config env
      endpoint = relayEndpoint options
  case cmd options of
    Send tfd ->
      ExceptT $ MagicWormhole.runClient endpoint (appID env) (side env) $ \session -> do
      password <- allocatePassword (wordList env)
      send env session (toS password) tfd
    Receive maybeCode ->
      ExceptT $ MagicWormhole.runClient endpoint (appID env) (side env) $ \session -> do
      code <- getWormholeCode session (wordList env) maybeCode
      receive env session code
  where
    getWormholeCode :: MagicWormhole.Session -> [(Text, Text)] -> Maybe Text -> IO Text
    getWormholeCode session wordlist Nothing = getCode session wordlist
    getWormholeCode _ _ (Just code) = return code

