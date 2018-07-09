{-# LANGUAGE OverloadedStrings #-}
module FileTransfer.Internal.Messages
  ( makeSenderHandshake
  , makeReceiverHandshake
  , makeSenderRecordKey
  , makeReceiverRecordKey
  )
where

import Protolude
import MagicWormhole

import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Hash (SHA256(..))
import qualified Crypto.Saltine.Internal.ByteSizes as ByteSizes
import Data.Hex (hex)
import Data.Text (toLower)

hkdf :: ByteString -> MagicWormhole.SessionKey -> ByteString -> ByteString
hkdf salt (MagicWormhole.SessionKey key) purpose =
  HKDF.expand (HKDF.extract salt key :: HKDF.PRK SHA256) purpose keySize
  where
    keySize = ByteSizes.secretBoxKey

data Purpose
  = SenderHandshake
  | ReceiverHandshake
  | SenderRecord
  | ReceiverRecord
  deriving (Eq, Show)

deriveKeyFromPurpose :: Purpose -> MagicWormhole.SessionKey -> ByteString
deriveKeyFromPurpose purpose key =
  hkdf salt key (purposeStr purpose)
  where
    salt = "" :: ByteString
    purposeStr :: Purpose -> ByteString
    purposeStr SenderHandshake = "transit_sender"
    purposeStr ReceiverHandshake = "transit_receiver"
    purposeStr SenderRecord = "transit_record_sender_key"
    purposeStr ReceiverRecord = "transit_record_receiver_key"

makeSenderHandshake :: MagicWormhole.SessionKey -> ByteString
makeSenderHandshake key =
  (toS @Text @ByteString "transit sender ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose SenderHandshake key
    hexid = (toS (toLower (toS @ByteString @Text (hex subkey))))


makeReceiverHandshake :: MagicWormhole.SessionKey -> ByteString
makeReceiverHandshake key =
  (toS @Text @ByteString "transit receiver ") <> hexid <> (toS @Text @ByteString " ready\n\n")
  where
    subkey = deriveKeyFromPurpose ReceiverHandshake key
    hexid = (toS (toLower (toS @ByteString @Text (hex subkey))))

makeSenderRecordKey :: MagicWormhole.SessionKey -> ByteString
makeSenderRecordKey = deriveKeyFromPurpose SenderRecord

makeReceiverRecordKey :: MagicWormhole.SessionKey -> ByteString
makeReceiverRecordKey = deriveKeyFromPurpose ReceiverRecord
