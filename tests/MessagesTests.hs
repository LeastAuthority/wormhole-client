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
    it "receiver handshake for key = b\"123\"" $ do
      makeReceiverHandshake (MagicWormhole.SessionKey (toS @Text @ByteString "123")) `shouldBe` (toS @Text @ByteString "transit receiver ED447528194BAC4C00D0C854B12A97CE51413D89AA74D6304475F516FDC23A1B ready\n\n")

