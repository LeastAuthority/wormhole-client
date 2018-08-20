module Main (main) where

import Protolude

import qualified ProtocolTests
import qualified MessagesTests
import qualified PipelineTests

main :: IO ()
main = do
  ProtocolTests.tests
  MessagesTests.tests
  PipelineTests.tests
  MessagesTests.messagesRoundTripTests >> return ()
