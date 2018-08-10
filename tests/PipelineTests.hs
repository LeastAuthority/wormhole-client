module PipelineTests
  ( tests
  )
where

import Protolude
import Test.Hspec
import Conduit ((.|))

import qualified Data.Conduit as C
import qualified Data.Conduit.Binary as CB
import qualified Data.Conduit.Serialization.Binary as CSB

import Data.Binary (Put)
import Data.Binary.Put (putCharUtf8, putWord32be)

import Transit.Internal.Pipeline

tests :: IO ()
tests = hspec $ do
  describe "assembleRecordC tests" $ do
    it "test with a small bytestring" $ do
      xs <- liftIO $ C.runConduitRes $
            CSB.sourcePut putChunk
            .| assembleRecordC
            .| CB.sinkLbs
      xs `shouldBe` "hello"
        where
          putChunk :: Put
          putChunk = do
            putWord32be (fromIntegral @Int 5)
            putCharUtf8 'h'
            putCharUtf8 'e'
            putCharUtf8 'l'
            putCharUtf8 'l'
            putCharUtf8 'o'
