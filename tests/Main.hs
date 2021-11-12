module Main (main) where

import Protolude

import qualified ProtocolTests
import qualified MessagesTests
import qualified PipelineTests
import qualified CryptoTests

main :: IO ()
main = do
  ProtocolTests.tests
  PipelineTests.tests
  MessagesTests.messagesRoundTripTests >>
    CryptoTests.cryptoRoundTripTests >>
    return ()
