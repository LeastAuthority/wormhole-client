-- | Description: a file-transfer monad transformer
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Transit.Internal.App
  ( Env(..)
  , App
  , prepareAppEnv
  , app
  , runApp
  , send
  , receive
  )
where

import Protolude hiding (toS)
import Protolude.Conv (toS)

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
import Control.Monad.Except (liftEither)
import Data.Text.PgpWordlist.Internal.Words (wordList)
import Data.Text.PgpWordlist.Internal.Types (EvenWord(..), OddWord(..))
import System.Directory (getTemporaryDirectory, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)

import Transit.Internal.Conf (Cmdline(..), Command(..), Options(..))
import Transit.Internal.Errors (Error(..), CommunicationError(..))
import Transit.Internal.FileTransfer(MessageType(..), sendFile, receiveFile)
import Transit.Internal.Peer (sendOffer, receiveOffer, receiveMessageAck, sendMessageAck, decodeTransitMsg)
import Transit.Internal.Network (connectToTor)

-- | Magic Wormhole transit app environment
data Env
  = Env { side :: MagicWormhole.Side
        -- ^ random 5-byte bytestring
        , config :: Cmdline
        -- ^ configuration like relay and transit url
        }

-- | Create an 'Env', given the AppID and 'Cmdline'
prepareAppEnv :: Cmdline -> IO Env
prepareAppEnv cmdlineOptions = do
  side' <- MagicWormhole.generateSide
  return $ Env side' cmdlineOptions

allocateCode :: [(Word8, EvenWord, OddWord)] -> IO Text
allocateCode wordlist = do
  g <- getStdGen
  let (r1, g') = randomR (0, 255) g
      (r2, _) = randomR (0, 255) g'
      Just (_, evenW, _) = atMay wordlist r2
      Just (_, _, oddW) = atMay wordlist r1
  return $ Text.concat [unOddWord oddW, "-", unEvenWord evenW]

printSendHelpText :: Text -> IO ()
printSendHelpText passcode = do
  TIO.putStrLn $  "Wormhole code is: " <> passcode
  TIO.putStrLn "On the other computer, please run:"
  TIO.putStrLn ""
  TIO.putStrLn $ "wormhole receive " <> passcode

data CompletionConfig
  = CompletionConfig {
       nameplates :: [Text]
    -- ^ List of nameplates identifiers on the server
     , oddWords :: [Text]
    -- ^ PGP Odd words
     , evenWords :: [Text]
    -- ^ PGP Even words
     , numWords :: Int
    -- ^ Number of PGP words used in wormhole code
     }

simpleCompletion :: Text -> HC.Completion
simpleCompletion text = (HC.simpleCompletion (toS text)) { HC.isFinished = False }

completeWord :: MonadIO m => CompletionConfig -> HC.CompletionFunc m
completeWord completionConfig = HC.completeWord Nothing "" completionFunc
  where
    completionFunc :: Monad m => String -> m [HC.Completion]
    completionFunc word = do
      let (completed, partial) = Text.breakOnEnd "-" (toS word)
          hypenCount = Text.count "-" completed
          wordlist | hypenCount == 0 = nameplates completionConfig
                   | odd hypenCount = oddWords completionConfig
                   | otherwise = evenWords completionConfig
          suffix = if hypenCount < numWords completionConfig
                      then "-"
                      else ""
          completions = map (\w -> completed `Text.append` (w `Text.append` suffix)) .
                        filter (Text.isPrefixOf partial) $ wordlist
      return $ map simpleCompletion completions

-- | Take an input code from the user with code completion.
-- In order for the code completion to work, we need to find
-- the possible open nameplates, the possible words and then
-- do the completion as the user types the code.
-- TODO: This function does too much. Perfect target for refactoring.
getCode :: MagicWormhole.Session -> [(Word8, EvenWord, OddWord)] -> IO Text
getCode session wordlist = do
  nameplates' <- MagicWormhole.list session
  let ns = [ n | MagicWormhole.Nameplate n <- nameplates' ]
      evens = [ unEvenWord n | (_, n, _) <- wordlist]
      odds  = [ unOddWord m | (_, _, m) <- wordlist]
      completionConfig = CompletionConfig {
                            nameplates = ns,
                            oddWords = odds,
                            evenWords = evens,
                            numWords = 2
                         }
  putText "Enter the receive wormhole code: "
  H.runInputT (settings completionConfig) getInput
  where
    settings :: MonadIO m => CompletionConfig -> H.Settings m
    settings completionConfig = H.Settings
      { H.complete = completeWord completionConfig
      , H.historyFile = Nothing
      , H.autoAddHistory = False
      }
    getInput :: H.InputT IO Text
    getInput = do
      minput <- H.getInputLine ""
      case minput of
        Nothing -> return ""
        Just input -> return (toS input)

-- | App Monad Transformer that reads the configuration from 'Env', runs
-- a computation over the IO Monad and returns either the value 'a' or 'Error'
newtype App a = App {
  getApp :: ReaderT Env (ExceptT Error IO) a
  } deriving (Functor, Applicative, Monad, MonadIO, MonadReader Env, MonadError Error)

-- | run the App Monad Transformer
runApp :: App a -> Env -> IO (Either Error a)
runApp appM env = runExceptT (runReaderT (getApp appM) env)

transitPurpose :: MagicWormhole.AppID -> ByteString
transitPurpose (MagicWormhole.AppID appid) = toS appid <> "/transit-key"

-- | Given the magic-wormhole session, appid, pass code, a function to print a helpful message
-- on the command the receiver needs to type (simplest would be just a `putStrLn`) and the
-- path on the disk of the sender of the file that needs to be sent, `sendFile` sends it via
-- the wormhole securely. The receiver, on successfully receiving the file, would compute
-- a sha256 sum of the encrypted file and sends it across to the sender, along with an
-- acknowledgement, which the sender can verify.
send :: MagicWormhole.Session -> Text -> MessageType -> Bool -> App ()
send session code tfd useTor = do
  env <- ask
  -- first establish a wormhole session with the receiver and
  -- then talk the filetransfer protocol over it as follows.
  let cmdlineOptions = config env
  let args = options cmdlineOptions
  let appid = appId args
  let transitserver = transitUrl args
  nameplate <- liftIO $ MagicWormhole.allocate session
  mailbox <- liftIO $ MagicWormhole.claim session nameplate
  peer <- liftIO $ MagicWormhole.open session mailbox  -- XXX: We should run `close` in the case of exceptions?
  let (MagicWormhole.Nameplate n) = nameplate
  let passcode = toS n <> "-" <> toS code
  liftIO $ printSendHelpText passcode
  result <- liftIO $ MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS passcode))
    (\conn ->
        case tfd of
          TMsg msg -> do
            let offer = MagicWormhole.Message msg
            sendOffer conn offer
            -- wait for "answer" message with "message_ack" key
            first NetworkError <$> receiveMessageAck conn
          TFile fileOrDirpath -> do
            let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
            bracket
              -- acquire resource
              (do
                  systemTmpDir <- getTemporaryDirectory
                  createTempDirectory systemTmpDir "wormhole")
              -- release resource
              removeDirectoryRecursive
              -- do the computation in between: send the file
              (sendFile conn transitserver transitKey fileOrDirpath useTor)
    )
  liftEither result

-- | receive a text message or file from the wormhole peer.
receive :: MagicWormhole.Session -> Text -> Bool -> App ()
receive session code useTor = do
  env <- ask
  -- establish the connection
  let cmdlineOptions = config env
  let args = options cmdlineOptions
  let appid = appId args
  let transitserver = transitUrl args
  let codeSplit = Text.split (=='-') code
  let (Just nameplate) = headMay codeSplit
  mailbox <- liftIO $ MagicWormhole.claim session (MagicWormhole.Nameplate nameplate)
  peer <- liftIO $ MagicWormhole.open session mailbox
  result <- liftIO $ MagicWormhole.withEncryptedConnection peer (Spake2.makePassword (toS (Text.strip code)))
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
            return $ bimap (const (NetworkError (ConnectionError "sending the ack message failed"))) identity result
          Right (MagicWormhole.File _ _) -> do
            sendMessageAck conn "not_ok"
            return $ Left (NetworkError (ConnectionError "did not expect a file offer"))
          Right MagicWormhole.Directory {} ->
            return $ Left (NetworkError (UnknownPeerMessage "directory offer is not supported"))
          -- ok, we received the Transit Message, send back a transit message
          Left received ->
            case decodeTransitMsg (toS received) of
              Left e -> return $ Left (NetworkError e)
              Right transitMsg -> do
                let transitKey = MagicWormhole.deriveKey conn (transitPurpose appid)
                receiveFile conn transitserver transitKey transitMsg useTor
    )
  liftEither result

-- | A file transfer application that takes an 'Env' and depending on the
-- config options, either sends or receives a file, directory or a text
-- message from the peer.
app :: App ()
app = do
  env <- ask
  let cmdlineOptions = config env
      args = options cmdlineOptions
      appid = appId args
      endpoint = relayEndpoint args
      command = cmd cmdlineOptions
  case command of
    Send tfd useTor -> do
      maybeSock <- maybeGetConnectionSocket endpoint useTor
      case maybeSock of
        Right sock' ->
          liftIO (MagicWormhole.runClient endpoint appid (side env) sock' $ \session ->
                     runApp (sendSession tfd session useTor) env) >>= liftEither
        Left e -> liftEither (Left e)
    Receive maybeCode useTor -> do
      maybeSock <- maybeGetConnectionSocket endpoint useTor
      case maybeSock of
        Right sock' ->
          liftIO (MagicWormhole.runClient endpoint appid (side env) sock' $ \session ->
                     runApp (receiveSession maybeCode session useTor) env) >>= liftEither
        Left e -> liftEither (Left e)
  where
    getWormholeCode :: MagicWormhole.Session -> Maybe Text -> IO Text
    getWormholeCode session Nothing = getCode session wordList
    getWormholeCode _ (Just code) = return code
    sendSession offerMsg session useTor = do
      code <- liftIO $ allocateCode wordList
      send session (toS code) offerMsg useTor
    receiveSession maybeCode session useTor = do
      code <- liftIO $ getWormholeCode session maybeCode
      receive session code useTor
    maybeGetConnectionSocket endpoint useTor | useTor == True = do
                                                 res <- liftIO $ connectToTor endpoint
                                                 return $ bimap NetworkError Just res
                                             | otherwise = return (Right Nothing)
                                               
