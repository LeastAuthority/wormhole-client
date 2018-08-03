module Transit.Internal.Crypto
  ( encrypt
  , decrypt
  , PlainText
  , CipherText
  , deriveKeyFromPurpose
  , Purpose(..)
  )
where

import Protolude

import qualified Data.ByteString as BS
import qualified Crypto.Saltine.Class as Saltine
import qualified Crypto.Saltine.Core.SecretBox as SecretBox
import Crypto.Saltine.Internal.ByteSizes (boxNonce)
import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Hash (SHA256(..))
import qualified Crypto.Saltine.Internal.ByteSizes as ByteSizes

type PlainText = ByteString
type CipherText = ByteString

-- | decrypt the bytestring representing ciphertext block with
-- the given key. It is assumed that the ciphertext bytestring
-- is nonce followed by the actual encrypted data.
decrypt :: SecretBox.Key -> CipherText -> Either Text PlainText
decrypt key ciphertext =
  -- extract nonce from ciphertext.
  let (nonceBytes, ct) = BS.splitAt boxNonce ciphertext
      nonce = fromMaybe (panic "unable to decode nonce") $
              Saltine.decode nonceBytes
      maybePlainText = SecretBox.secretboxOpen key nonce ct
  in
    case maybePlainText of
      Just pt -> Right pt
      Nothing -> Left "decryption error"

-- | encrypt the given chunk with the given secretbox key and nonce.
-- Saltine's nonce seem represented as a big endian bytestring.
-- However, to interop with the wormhole python client, we need to
-- use and send nonce as a little endian bytestring.
encrypt :: SecretBox.Key -> SecretBox.Nonce -> PlainText -> CipherText
encrypt key nonce plaintext =
  let nonceLE = BS.reverse $ toS $ Saltine.encode nonce
      newNonce = fromMaybe (panic "nonce decode failed") $
                 Saltine.decode (toS nonceLE)
      ciphertext = toS $ SecretBox.secretbox key newNonce plaintext
  in
    nonceLE <> ciphertext

hkdf :: ByteString -> SecretBox.Key -> ByteString -> ByteString
hkdf salt key purpose =
  HKDF.expand (HKDF.extract salt (Saltine.encode key) :: HKDF.PRK SHA256) purpose keySize
  where
    keySize = ByteSizes.secretBoxKey

-- | Various purpose types for key derivation.
--
-- Normally used with 'deriveKeyFromPurpose'.
data Purpose
  = SenderHandshake
  -- ^ Purpose type to be used by transit sender.
  | ReceiverHandshake
  -- ^ Purpose type to be used by transit receiver.
  | SenderRecord
  -- ^ Purpose type to be used for encrypting records.
  | ReceiverRecord
  -- ^ Purpose type to be used for decrypting records.
  deriving (Eq, Show)

-- | derive a new purpose-specific key from a master key.
deriveKeyFromPurpose :: Purpose -> SecretBox.Key -> ByteString
deriveKeyFromPurpose purpose key =
  hkdf salt key (purposeStr purpose)
  where
    salt = "" :: ByteString
    purposeStr :: Purpose -> ByteString
    purposeStr SenderHandshake = "transit_sender"
    purposeStr ReceiverHandshake = "transit_receiver"
    purposeStr SenderRecord = "transit_record_sender_key"
    purposeStr ReceiverRecord = "transit_record_receiver_key"