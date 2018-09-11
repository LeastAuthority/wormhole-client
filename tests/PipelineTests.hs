module PipelineTests
  ( tests
  )
where

import Protolude hiding (putByteString, Selector)

import Test.Hspec
import Conduit ((.|))

import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Data.Conduit as C
import qualified Data.Conduit.Binary as CB
import qualified Data.Conduit.Serialization.Binary as CSB
import qualified Data.ByteString as BS

import Data.Binary (Put)
import Data.Binary.Put (putWord32be, putByteString)

import Transit.Internal.Pipeline
import Transit.Internal.Crypto (CryptoError)

tests :: IO ()
tests = hspec $ do
  describe "assembleRecordC tests" $ do
    it "tests assembleRecordC with a short bytestring input" $ do
      let str = "hello" :: ByteString
      xs <- liftIO $ C.runConduitRes $
            CSB.sourcePut (putChunk str)
            .| assembleRecordC
            .| CB.isolate (BS.length str)
            .| CB.sinkLbs
      xs `shouldBe` (toS str)

  describe "decryptC tests" $ do
    it "tests a encryptC/decryptC round trip" $ do
      let key = fromMaybe (panic "cannot decode key") $
                Saltine.decode ("0123456789abcdef0123456789abcdef" :: ByteString)
          plaintext = "foobar" :: ByteString
      xs <- liftIO (C.runConduitRes $
              CSB.sourcePut (putByteString plaintext)
              .| encryptC key
              .| assembleRecordC
              .| decryptC key
              .| CB.isolate (BS.length plaintext)
              .| CB.sinkLbs)
      xs `shouldBe` (toS plaintext)

    it "throws CryptoError when a wrong nonce is encountered" $ do
      -- create a packet with a non-zero nonce concatenated with
      -- random input. Feed it as a source into decryptC and feed
      -- output into a sinkLbs. This should throw a BadNonce
      -- exception, as decryptC expects a nonce/sequence number of 0.
      let nonce = Saltine.nudge Saltine.zero :: SecretBox.Nonce
          key = fromMaybe (panic "cannot decode key") $
                Saltine.decode ("0123456789abcdef0123456789abcdef" :: ByteString)
          nonceBytes = Saltine.encode nonce
          plaintext = "foobar" :: ByteString
          packet = nonceBytes <> plaintext
      liftIO (C.runConduitRes $
              CSB.sourcePut (putByteString packet)
              .| decryptC key
              .| CB.isolate (BS.length packet)
              .| CB.sinkLbs)
        `shouldThrow` cryptoError
        where
          putChunk :: ByteString -> Put
          putChunk s = do
            let strlen = BS.length s
            putWord32be (fromIntegral @Int strlen)
            putByteString s
          cryptoError :: Selector CryptoError
          cryptoError = const True
