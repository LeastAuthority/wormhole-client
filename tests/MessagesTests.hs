{-# LANGUAGE OverloadedStrings #-}
module MessagesTests
  ( tests
  , messagesRoundTripTests
  )
where

import Protolude hiding (toS)
import Protolude.Conv (toS)

import qualified Data.Set as Set

import Transit.Internal.Messages

import Test.Hspec
import Data.Aeson
  ( encode
  , decode
  , eitherDecode
  )
import Hedgehog (forAll, property, Property, Group(..), checkSequential, tripping)
import qualified Generator

tests :: IO ()
tests = hspec $ do
  describe "Ability tests" $ do
    it "encode Ability" $ do
      encode DirectTcpV1 `shouldBe` "\"direct-tcp-v1\""
      encode TorTcpV1 `shouldBe` "\"tor-tcp-v1\""
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
      encode h1 `shouldBe` "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"port\":1234,\"type\":\"direct-tcp-v1\"}"
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
      encode ch1 `shouldBe` "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"port\":1234,\"type\":\"direct-tcp-v1\"}"
    it "encode Relay ConnectionHint" $ do
      let h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
          ch1 = Relay { rtype = RelayV1
                      , hints = [h1] }
      encode ch1 `shouldBe` "{\"hints\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"port\":1234,\"type\":\"direct-tcp-v1\"}],\"type\":\"relay-v1\"}"
    it "decode Direct ConnectionHint" $ do
      let h1text = "{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}" :: Text
      decode (toS h1text) `shouldBe`  Just (Direct Hint { ctype = DirectTcpV1
                                                        , priority = 0.5
                                                        , hostname = "foo.bar.baz"
                                                        , port = 1234 })
    it "decode Relay ConnectionHint" $ do
      let h1text = "{\"type\": \"relay-v1\", \"hints\": [{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"type\":\"direct-tcp-v1\",\"port\":1234}]}" :: Text
          h1 = Hint { ctype = DirectTcpV1
                    , priority = 0.5
                    , hostname = "foo.bar.baz"
                    , port = 1234 }
      decode (toS h1text) `shouldBe` Just Relay { rtype = RelayV1
                                                , hints = [h1] }

    it "encode and decode Transit type" $ do
      let t1 = Transit { abilitiesV1 = [Ability DirectTcpV1, Ability RelayV1]
                       , hintsV1 = Set.fromList [ch1, ch2] }
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
          t2 = Transit { abilitiesV1 = [Ability DirectTcpV1, Ability RelayV1]
                       , hintsV1 = Set.fromList [ch3 ,ch4] }
          t1text = "{\"transit\":{\"abilities-v1\":[{\"type\":\"direct-tcp-v1\"},{\"type\":\"relay-v1\"}],\"hints-v1\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"port\":1234,\"type\":\"direct-tcp-v1\"},{\"hints\":[{\"hostname\":\"foo.bar.baz\",\"priority\":0.5,\"port\":1234,\"type\":\"direct-tcp-v1\"}],\"type\":\"relay-v1\"}]}}" :: Text
          t2text = "{\"transit\": {\"abilities-v1\": [{\"type\": \"direct-tcp-v1\"}, {\"type\": \"relay-v1\"}], \"hints-v1\": [{\"priority\": 0.0, \"hostname\": \"192.168.1.106\", \"type\": \"direct-tcp-v1\", \"port\": 36097}, {\"type\": \"relay-v1\", \"hints\": [{\"priority\": 0.0, \"hostname\": \"transit.magic-wormhole.io\", \"type\": \"direct-tcp-v1\", \"port\": 4001}]}]}}" :: ByteString
      encode t1 `shouldBe` toS t1text
      decode (encode t1) `shouldBe` Just t1
      decode (toS t2text) `shouldBe` Just t2

  describe "Ack message tests" $ do
    it "encode and decode FileAck responses" $ do
      let f1 = FileAck "ok"
      encode f1 `shouldBe` "{\"file_ack\":\"ok\"}"
      decode (encode f1) `shouldBe` Just f1

  describe "Response message tests" $ do
    it "encode and decode Error response" $ do
      let r1 = Error "transfer rejected"
      encode r1 `shouldBe` "{\"error\":\"transfer rejected\"}"
      decode (encode r1) `shouldBe` Just r1
    it "encode and decode answer response" $ do
      let a1 = Answer (FileAck "ok")
      encode a1 `shouldBe` "{\"answer\":{\"file_ack\":\"ok\"}}"
      decode (encode a1) `shouldBe` Just a1
      
  describe "Transit Ack tests" $ do
    it "encode and decode Transit Ack from receiver to sender" $ do
      let a1 = TransitAck "ok" "e4f1684a5375ebf7f1dcde02a66026f937a8c6195adf31813ef21b3ccadfb11f"
      encode a1 `shouldBe` "{\"ack\":\"ok\",\"sha256\":\"e4f1684a5375ebf7f1dcde02a66026f937a8c6195adf31813ef21b3ccadfb11f\"}"
      decode (encode a1) `shouldBe` Just a1

prop_abilityTrip :: Property
prop_abilityTrip = property $ do
  x <- forAll Generator.abilityGen
  tripping x encode eitherDecode

prop_hintTrip :: Property
prop_hintTrip = property $ do
  x <- forAll Generator.hintGen
  tripping x encode eitherDecode

prop_connectionHintTrip :: Property
prop_connectionHintTrip = property $ do
  x <- forAll Generator.connectionHintGen
  tripping x encode eitherDecode

prop_ackTrip :: Property
prop_ackTrip = property $ do
  x <- forAll Generator.ackGen
  tripping x encode eitherDecode

prop_transitMsgTrip :: Property
prop_transitMsgTrip = property $ do
  x <- forAll Generator.transitMsgGen
  tripping x encode eitherDecode

prop_transitAckTrip :: Property
prop_transitAckTrip = property $ do
  x <- forAll Generator.transitAckGen
  tripping x encode eitherDecode

messagesRoundTripTests :: IO Bool
messagesRoundTripTests =
  checkSequential $ Group "Messages"
  [ ("prop_abilityTrip", prop_abilityTrip)
  , ("prop_hintTrip", prop_hintTrip)
  , ("prop_connectionHintTrip", prop_connectionHintTrip)
  , ("prop_ackTrip", prop_ackTrip)
  , ("prop_transitMsgTrip", prop_transitMsgTrip)
  , ("prop_transitAckTrip", prop_transitAckTrip)
  ]

