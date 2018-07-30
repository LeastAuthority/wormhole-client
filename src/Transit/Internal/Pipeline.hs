module Transit.Internal.Pipeline
  ( encryptC
  , decryptC
  , assembleRecordC
  , sha256PassThroughC
  , passThroughBytesC
  )
where

import Protolude

import Crypto.Hash (SHA256(..))
import qualified Crypto.Hash as Hash
import qualified Conduit as C
import qualified Data.Binary.Builder as BB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder(toLazyByteString, word32BE)
import Data.Binary.Get (getWord32be, runGet)
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Crypto.Saltine.Class as Saltine
import Crypto.Saltine.Internal.ByteSizes (boxNonce)

import Transit.Internal.Network
import Transit.Internal.Crypto

encryptC :: Monad m => SecretBox.Key -> C.ConduitT ByteString ByteString m ()
encryptC key = go Saltine.zero
  where
    go nonce = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just chunk -> do
          let cipherText = encrypt key nonce chunk
              cipherTextSize = toLazyByteString (word32BE (fromIntegral (BS.length cipherText)))
          C.yield (toS cipherTextSize)
          C.yield cipherText
          go (Saltine.nudge nonce)

decryptC :: MonadIO m => SecretBox.Key -> C.ConduitT ByteString ByteString m ()
decryptC key = loop
  where
    loop = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just bs -> do
          let (nonceBytes, ciphertext) = BS.splitAt boxNonce bs
              nonce = fromMaybe (panic "unable to decode nonce") $
                Saltine.decode nonceBytes
              maybePlainText = SecretBox.secretboxOpen key nonce ciphertext
          case maybePlainText of
            Just plaintext -> do
              C.yield plaintext
              loop
            Nothing -> throwIO (CouldNotDecrypt "SecretBox failed to open")

sha256PassThroughC :: (Monad m) => C.ConduitT ByteString ByteString m Text
sha256PassThroughC = go $! Hash.hashInitWith SHA256
  where
    go :: (Monad m) => Hash.Context SHA256 -> C.ConduitT ByteString ByteString m Text
    go ctx = do
      b <- C.await
      case b of
        Nothing -> return $! (show (Hash.hashFinalize ctx))
        Just bs -> do
          C.yield bs
          go $! Hash.hashUpdate ctx bs

assembleRecordC :: Monad m => C.ConduitT ByteString ByteString m ()
assembleRecordC = do
  b <- C.await
  case b of
    Nothing -> return ()
    Just bs -> do
      let (hdr, pkt) = BS.splitAt 4 bs
      let len = runGet getWord32be (BL.fromStrict hdr)
      getChunk (fromIntegral len - BS.length pkt) (BB.fromByteString pkt)

getChunk :: Monad m => Int -> BB.Builder -> C.ConduitT ByteString ByteString m ()
getChunk len bb = go len bb
  where
    go size res = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just bs | size == BS.length bs -> do
                    C.yield $! toS (BB.toLazyByteString res) <> bs
                    assembleRecordC
                | size < BS.length bs -> do
                    let (f, l) = BS.splitAt size bs
                    C.leftover l
                    C.yield (toS (BB.toLazyByteString res) <> f)
                    assembleRecordC
                | otherwise -> do
                    go (size - BS.length bs) (res <> BB.fromByteString bs)

passThroughBytesC :: Monad m => Int -> C.ConduitT ByteString ByteString m ()
passThroughBytesC len = go len
  where
    go n | n <= 0 = return ()
         | otherwise = do
             b <- C.await
             case b of
               Nothing -> return ()
               Just bs -> do
                 C.yield bs
                 go (n - (BS.length bs))

