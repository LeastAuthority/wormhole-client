module Main (main) where

import Protolude

import qualified FileTransferTests
import qualified MessagesTests

main :: IO ()
main = do
  FileTransferTests.tests
  MessagesTests.tests
