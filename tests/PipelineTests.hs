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
import qualified Data.Text as T

import Data.String (String)
import Data.Binary (Put)
import Data.Binary.Put (putStringUtf8, putWord32be)

import Transit.Internal.Pipeline

tests :: IO ()
tests = hspec $ do
  describe "assembleRecordC tests" $ do
    it "test with a small bytestring" $ do
      xs <- liftIO $ C.runConduitRes $
            CSB.sourcePut (putChunk str)
            .| assembleRecordC
            .| CB.isolate (T.length str)
            .| CB.sinkLbs
      xs `shouldBe` "hello"
        where
          str = "hello"
          putChunk :: Text -> Put
          putChunk s = do
            putWord32be (fromIntegral @Int 5)
            putStringUtf8 (toS @Text @String s)
