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
  describe "Ability tests" $ do
    it "encode Ability" $ do
      encode DirectTcpV1 `shouldBe` "\"direct-tcp-v1\""
      encode RelayV1 `shouldBe` "\"relay-v1\""
    it "decode Ability" $ do
      let s1 = "\"direct-tcp-v1\"" :: Text
      decode (toS s1) `shouldBe` Just DirectTcpV1
      let s2 = "\"relay-v1\"" :: Text
      decode (toS s2) `shouldBe` Just RelayV1
  describe "Hint tests" $ do
    it "encode Hint" $ do
      let h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
      encode h1 `shouldBe` "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}"
    it "decode Hint" $ do
      let h1 = "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}" :: Text
      decode (toS h1) `shouldBe` Just Hint { ctype = DirectTcpV1
                                           , priority = 0.5
                                           , hostname = "foo.bar.baz"
                                           , port = 1234 }
  describe "ConnectionHint tests" $ do
    it "encode Direct ConnectionHint" $ do
      let h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
          ch1 = Direct h1
      encode ch1 `shouldBe` "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}"
    it "encode Relay ConnectionHint" $ do
      let h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
          ch1 = Relay { rtype = RelayV1
                      , hints = [h1] }
      encode ch1 `shouldBe` "{\"hints\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}],\"type\":\"relay-v1\"}"
    it "decode Direct ConnectionHint" $ do
      let h1text = "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}" :: Text
      decode (toS h1text) `shouldBe`  Just (Direct (Hint { ctype = DirectTcpV1
                                                         , priority = 0.5
                                                         , hostname = "foo.bar.baz"
                                                         , port = 1234 }))
    it "decode Relay ConnectionHint" $ do
      let h1text = "{\"type\": \"relay-v1\", \"hints\": [{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}]}" :: Text
          h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
      decode (toS h1text) `shouldBe` Just (Relay { rtype = RelayV1
                                                 , hints = [h1] })

    it "encode and decode Transit type" $ do
      let t1 = Transit { abilitiesV1 = [DirectTcpV1, RelayV1]
                       , hintsV1 = [ch1, ch2] }
          h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
          ch1 = Direct h1
          h2 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
          ch2 = Relay { rtype = RelayV1
                      , hints = [h2] }
          t1text = "{\"transit\":{\"hints-v1\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234},{\"hints\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}],\"type\":\"relay-v1\"}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"},{\"type\":\"relay-v1\"}]}}" :: Text
      decode (encode t1) `shouldBe` (Just t1)


{-|
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
          abilities' = [connectionType']
          hints' = [connHint1]
          connectionType' = DirectTCP
          connHint1 = Direct { name = "direct-tcp-v1"
                             , priority = 1.5
                             , hostname = "127.0.0.1"
                             , port = PortNum 10110 }
      decode transitMsg `shouldBe` Just (Transit abilities' hints')

    it "encode transit message with direct and relay hints" $ do
      let connHint1 = Direct { name = "direct-tcp-v1"
                             , priority = 1.5
                             , hostname = "127.0.0.1"
                             , port = PortNum 10110 }
          connHint2 = Relay { name = "relay-v1"
                             , priority = 1.5
                             , hostname = "transit.magic-wormhole.io"
                             , port = PortNum 10110 }
          abilities' = [DirectTCP, RelayTCP]
          hints' = [connHint1, connHint2]
          transitMsg = Transit abilities' hints'
      encode transitMsg `shouldBe` "{\"transit\":{\"hints-v1\":[{\"hostname\":\"127.0.0.1\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110},{\"hints\":[{\"hostname\":\"transit.magic-wormhole.io\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110}],\"type\":\"relay-v1\"}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"},{\"type\":\"relay-v1\"}]}}"

    it "decode transit message with direct and relay hints" $ do
      let transitMsg = "{\"transit\":{\"hints-v1\":[{\"hostname\":\"127.0.0.1\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110},{\"hints\":{\"hostname\":\"transit.magic-wormhole.io\",\"priority\":1.5,\"type\":\"direct-tcp-v1\",\"port\":10110},\"type\":\"relay-v1\"}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"},{\"type\":\"relay-v1\"}]}}"
      decode transitMsg `shouldBe` (Just (Transit {abilities = [DirectTCP,RelayTCP], hints = [Direct {name = "direct-tcp-v1", priority = 1.5, hostname = "127.0.0.1", port = PortNum {getPortNumber = 10110}},Relay {name = "direct-tcp-v1", priority = 1.5, hostname = "transit.magic-wormhole.io", port = PortNum {getPortNumber = 10110}}]}))

    it "decode transit message" $ do
      let transitMsg = "{\"transit\": {\"abilities-v1\": [{\"type\": \"direct-tcp-v1\"}, {\"type\": \"relay-v1\"}], \"hints-v1\": [{\"priority\": 0.0, \"hostname\": \"192.168.1.106\", \"type\": \"direct-tcp-v1\", \"port\": 41319}, {\"type\": \"relay-v1\", \"hints\": [{\"priority\": 0.0, \"hostname\": \"transit.magic-wormhole.io\", \"type\": \"direct-tcp-v1\", \"port\": 4001}]}]}}"

|-}
