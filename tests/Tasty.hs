module Main (main) where

import Protolude

import qualified FileTransferTests

main :: IO ()
main = do
  FileTransferTests.tests

