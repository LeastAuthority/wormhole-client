module MessagesTests
  ( tests
  )
where

import Protolude
import Test.Hspec
import qualified MagicWormhole

import FileTransfer.Internal.Messages

tests :: IO ()
tests = hspec $ do
  describe "sender handshake tests" $ do
    it "sender handshake for key = b\"123\"" $ do
      makeSenderHandshake (MagicWormhole.SessionKey (toS @Text @ByteString "123")) `shouldBe` (toS @Text @ByteString "transit sender 559BDEAE4B49FA6A23378D2B68F4C7E69378615D4AF049C371C6A26E82391089 ready\n\n")

