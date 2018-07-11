module ProtocolTests
  ( tests
  )
where

import Protolude
import Test.Hspec
import qualified Crypto.Saltine.Class as Saltine

import Transit.Internal.Peer

tests :: IO ()
tests = hspec $ do
  describe "sender handshake tests" $ do
    it "sender handshake for a fixed key" $ do
      let skey = (fromMaybe (panic "error decoding bytestring into secretbox key") $ Saltine.decode (toS @Text @ByteString "12345678901234567890123456789012"))
      makeSenderHandshake skey `shouldBe` (toS @Text @ByteString "transit sender 8114b57043e22ca82f05b3aa21612bbcd403e6aa9b11e4a336dd749771775fa1 ready\n\n")
    it "receiver handshake for a fixed key" $ do
      let rkey = (fromMaybe (panic "error decoding bytestring into secretbox key") $ Saltine.decode (toS @Text @ByteString "12345678901234567890123456789012"))
      makeReceiverHandshake rkey `shouldBe` (toS @Text @ByteString "transit receiver 3b0d65f31e63b490b4edc13cf27a8b09cfb53c479f8ab67bc984e9f392ea28f4 ready\n\n")

