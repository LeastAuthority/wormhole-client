module FileTransferTests
  ( tests
  )
where

import Protolude

import FileTransfer

import Test.Hspec
import Test.QuickCheck
import Data.Aeson
  ( encode
  , decode
--  , ToJSON(..)
--  , FromJSON(..)
  )

tests :: IO ()
tests = hspec $ do
  describe "PortNum tests" $ do
    it "encode portnum" $ do
      let port = PortNum 8080
      encode port `shouldBe` "8080"
    it "decode portnum" $ do
      decode "8080" `shouldBe` Just (PortNum 8080)
    it "encode-decode cycle for portnum" $ do
      decode (encode (PortNum 8080)) `shouldBe` Just (PortNum 8080)
  describe "ConnectionHint tests" $ do
    it "encode direct hint" $ do
      let directHint1 = Direct { name = "direct-tcp-v1"
                               , priority = 1.5
                               , hostname = "127.0.0.1"
                               , port = PortNum 10110 }
      encode directHint1 `shouldBe`
        "{\"hostname\":\"127.0.0.1\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110}"
    it "encode and decode direct hint" $ do
      let directHint1 = Direct { name = "direct-tcp-v1"
                               , priority = 1.5
                               , hostname = "127.0.0.1"
                               , port = PortNum 10110 }
      decode (encode directHint1) `shouldBe`
        Just directHint1
  describe "ConnectionType tests" $ do
    it "encode connection type DirectTCP" $ do
      encode DirectTCP `shouldBe` "{\"type\":\"direct-tcp-v1\"}"
    it "encode connection type RelayTCP" $ do
      encode RelayTCP `shouldBe` "{\"type\":\"relay-v1\"}"
    it "decode connection type DirectTCP" $ do
      decode "{\"type\":\"direct-tcp-v1\"}" `shouldBe` Just DirectTCP
    it "decode connection type RelayTCP" $ do
      decode "{\"type\":\"relay-v1\"}" `shouldBe` Just RelayTCP
  describe "Transit tests" $ do
    it "encode transit message with only direct hint" $ do
      let connHint1 = Direct { name = "direct-tcp-v1"
                             , priority = 1.5
                             , hostname = "127.0.0.1"
                             , port = PortNum 10110 }
          connectionType' = DirectTCP
          abilities' = [connectionType']
          hints' = [connHint1]
          transitMsg = Transit abilities' hints'
      encode transitMsg `shouldBe` "{\"transit\":{\"hints-v1\":[{\"hostname\":\"127.0.0.1\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"}]}}"
    it "decode transit message with only direct hint" $ do
      let transitMsg = "{\"transit\":{\"hints-v1\":[{\"hostname\":\"127.0.0.1\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"}]}}"
      decode transitMsg `shouldBe` Just (Transit abilities' hints')
        where
          abilities' = [connectionType']
          hints' = [connHint1]
          connectionType' = DirectTCP
          connHint1 = Direct { name = "direct-tcp-v1"
                             , priority = 1.5
                             , hostname = "127.0.0.1"
                             , port = PortNum 10110 }

