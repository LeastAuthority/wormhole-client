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

import qualified Crypto.Hash as Hash
import qualified Conduit as C
import qualified Data.Conduit.Network as CN
import qualified Data.Conduit.Binary as CB
import qualified Data.Binary.Builder as BB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import qualified Crypto.Saltine.Class as Saltine

import Transit.Internal.Network (TCPEndpoint(..), CommunicationError(..))
import Transit.Internal.Crypto (encrypt)

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
    .| sha256PassThroughC `C.fuseBoth` C.sinkFileCautious fp

encryptC :: MonadIO m => SecretBox.Key -> C.ConduitT ByteString ByteString m ()
encryptC key = loop Saltine.zero
  where
    loop nonce = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just chunk -> do
          let cipherText = encrypt key nonce chunk
          case cipherText of
            Right cipherText' -> do
              let cipherTextSize = toLazyByteString (word32BE (fromIntegral (BS.length cipherText')))
              C.yield (toS cipherTextSize)
              C.yield cipherText'
              loop (Saltine.nudge nonce)
            Left e -> throwIO e

decryptC :: MonadIO m => SecretBox.Key -> C.ConduitT ByteString ByteString m ()
decryptC key = loop Saltine.zero
  where
    loop :: MonadIO m => SecretBox.Nonce -> C.ConduitT ByteString ByteString m ()
    loop seqNum = do
      b <- C.await
      case b of
        Nothing -> return ()
        Just bs -> do
          case decrypt key bs of
            Right (plainText, nonce) -> do
              let seqNumLE = BS.reverse $ toS $ Saltine.encode seqNum
                  seqNum' = Saltine.decode (toS seqNumLE)
              if Just nonce /= seqNum'
                then throwIO (BadNonce "nonce decoding failed or packets received out of order.")
                else do
                C.yield plainText
                loop (Saltine.nudge seqNum)
            Left e -> throwIO e

sha256PassThroughC :: (Monad m) => C.ConduitT ByteString ByteString m Text
sha256PassThroughC = loop $! Hash.hashInitWith SHA256
  where
    loop :: (Monad m) => Hash.Context SHA256 -> C.ConduitT ByteString ByteString m Text
    loop ctx = do
      b <- C.await
      case b of
        Nothing -> return $! show (Hash.hashFinalize ctx)
        Just bs -> do
          C.yield bs
          loop $! Hash.hashUpdate ctx bs

-- | The decryption conduit computation would succeed only if a complete
-- bytestream that represents an encrypted block of data is given to it.
-- However, the upstream elements may chunk the data for which one may not
-- have control of. The encrypted packet on the wire has a 4-byte length
-- header, so we could first read it and assemble a complete encrypted
-- block into downstream.
assembleRecordC :: Monad m => C.ConduitT ByteString ByteString m ()
assembleRecordC = do
  hdr <- getChunk 4
  let len = runGet getWord32be (BL.fromStrict hdr)
  packet <- getChunk (fromIntegral len)
  C.yield packet
  assembleRecordC
  where
    getChunk :: Monad m => Int -> C.ConduitT ByteString ByteString m ByteString
    getChunk size = go size BB.empty
    go :: Monad m => Int -> BB.Builder -> C.ConduitT ByteString ByteString m ByteString
    go size res = do
      let residue = BL.toStrict . BB.toLazyByteString $ res
      b <- C.await
      case b of
        Nothing -> return residue
        Just bs | size < BS.length bs -> do
                    let (f, l) = BS.splitAt size bs
                    C.leftover l
                    return $ residue <> f
                | size == BS.length bs -> do
                    return (residue <> bs)
                | otherwise -> do
                    let want = size - BS.length bs
                    go want $ BB.fromByteString (residue <> bs)

