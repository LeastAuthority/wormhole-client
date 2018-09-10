module Transit.Internal.App
  ( Env(..)
  , prepareAppEnv
  )
where

import Protolude

import qualified Data.Text as Text
import qualified Data.Text.IO as TIO
import qualified MagicWormhole

import Transit.Internal.Conf(Options)
import Paths_hwormhole

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

-- newtype AppM a = AppM ( Env -> IO (Either AppError a) )
-- type AppM a = ReaderT Env (EitherT AppError IO a)

