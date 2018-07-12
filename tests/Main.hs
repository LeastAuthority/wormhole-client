module Main (main) where

import Protolude

import qualified ProtocolTests
import qualified MessagesTests

main :: IO ()
main = do
  ProtocolTests.tests
  MessagesTests.tests
  MessagesTests.messagesRoundTripTests >> return ()
