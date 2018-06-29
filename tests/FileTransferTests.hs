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
          h3 = Hint { ctype = DirectTcpV1
                    , priority = 0.0
                    , hostname = "192.168.1.106"
                    , port = 36097 }
          ch3 = Direct h3
          h4 = Hint { ctype = DirectTcpV1
                    , priority = 0.0
                    , hostname = "transit.magic-wormhole.io"
                    , port = 4001 }
          ch4 = Relay { rtype = RelayV1
                      , hints = [h4] }
          t2 = Transit { abilitiesV1 = [DirectTcpV1,RelayV1]
                       , hintsV1 = [ch3 ,ch4] }
          t1text = "{\"transit\":{\"hints-v1\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234},{\"hints\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}],\"type\":\"relay-v1\"}],\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"},{\"type\":\"relay-v1\"}]}}" :: Text
          t2text = "{\"transit\": {\"abilities-v1\": [{\"type\": \"direct-tcp-v1\"}, {\"type\": \"relay-v1\"}], \"hints-v1\": [{\"priority\": 0.0, \"hostname\": \"192.168.1.106\", \"type\": \"direct-tcp-v1\", \"port\": 36097}, {\"type\": \"relay-v1\", \"hints\": [{\"priority\": 0.0, \"hostname\": \"transit.magic-wormhole.io\", \"type\": \"direct-tcp-v1\", \"port\": 4001}]}]}}" :: ByteString
      decode (encode t1) `shouldBe` (Just t1)
      decode (toS t2text) `shouldBe` Just t2

