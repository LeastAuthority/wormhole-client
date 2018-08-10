module Transit.Internal.Pipeline
  ( sendPipeline
  , receivePipeline
  -- * for tests
  , assembleRecordC
  )
where

import Protolude

import Crypto.Hash (SHA256(..))
import Data.Conduit ((.|))
import Data.ByteString.Builder(toLazyByteString, word32BE)
import Data.Binary.Get (getWord32be, runGet)
import Crypto.Saltine.Internal.ByteSizes (boxNonce)
import System.FilePath ((</>))

import qualified Crypto.Hash as Hash
import qualified Conduit as C
import qualified Data.Conduit.Network as CN
import qualified Data.Conduit.Binary as CB
import qualified Data.Binary.Builder as BB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Crypto.Saltine.Class as Saltine

import Transit.Internal.Network
import Transit.Internal.Crypto

-- | Given the peer network socket and the file path to be sent, this Conduit
-- pipeline reads the file, encrypts and send it over the network. A sha256
-- sum is calculated on the input before encryption to compare with the
-- receiver's decrypted copy.
sendPipeline :: C.MonadResource m =>
                FilePath
             -> TCPEndpoint
             -> SecretBox.Key
             -> C.ConduitM a c m (Text, ())
sendPipeline fp (TCPEndpoint s) key =
  C.sourceFile fp .| sha256PassThroughC `C.fuseBoth` (encryptC key .| CN.sinkSocket s)

-- | Receive the encrypted bytestream from a network socket, decrypt it and
-- write it into a file, also calculating the sha256 sum of the decrypted
-- output along the way.
receivePipeline :: C.MonadResource m =>
                   FilePath
                -> Int
                -> TCPEndpoint
                -> SecretBox.Key
                -> C.ConduitM a c m (Text, ())
receivePipeline fp len (TCPEndpoint s) key =
    CN.sourceSocket s
    .| assembleRecordC
    .| decryptC key
    .| CB.isolate len
    .| sha256PassThroughC `C.fuseBoth` C.sinkFileCautious ("./" </> fp)

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
        Nothing -> return $! show (Hash.hashFinalize ctx)
        Just bs -> do
          C.yield bs
          go $! Hash.hashUpdate ctx bs

-- | The decryption conduit computation would succeed only if a complete
-- bytestream that represents an encrypted block of data is given to it.
-- However, the upstream elements may chunk the data for which one may not
-- have control of. The encrypted packet on the wire has a 4-byte length
-- header, so we could first read it and assemble a complete encrypted
-- block into downstream.
assembleRecordC :: Monad m => C.ConduitT ByteString ByteString m ()
assembleRecordC = do
  b <- C.await
  case b of
    Nothing -> return ()
    Just bs | BS.length bs < 4 -> do
                C.leftover bs
                assembleRecordC
            | otherwise -> do
                let (hdr, pkt) = BS.splitAt 4 bs
                let len = runGet getWord32be (BL.fromStrict hdr)
                getChunk (fromIntegral len - BS.length pkt) (BB.fromByteString pkt)
  where
    getChunk :: Monad m => Int -> BB.Builder -> C.ConduitT ByteString ByteString m ()
    getChunk size res = do
      b <- C.await
      case b of
        Nothing -> C.yield (toS (BB.toLazyByteString res))
        Just bs | size == BS.length bs -> do
                    C.yield $! toS (BB.toLazyByteString res) <> bs
                    assembleRecordC
                | size < BS.length bs -> do
                    let (f, l) = BS.splitAt size bs
                    C.leftover l
                    C.yield (toS (BB.toLazyByteString res) <> f)
                    assembleRecordC
                | otherwise ->
                    getChunk (size - BS.length bs) (res <> BB.fromByteString bs)

