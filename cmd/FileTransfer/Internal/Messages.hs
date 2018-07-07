{-# LANGUAGE OverloadedStrings #-}
module FileTransfer.Internal.Messages
  ( makeSenderHandshake
  , makeReceiverHandshake
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

makeSenderHandshake :: MagicWormhole.SessionKey -> ByteString
makeSenderHandshake key =
    let hexid = hex $ hkdf salt key purpose
        salt = "" :: ByteString
        purpose = toS @Text @ByteString "transit_sender"
        hexid' = (toS (toLower (toS @ByteString @Text hexid)))
    in
      (toS @Text @ByteString "transit sender ") <> hexid' <> (toS @Text @ByteString " ready\n\n")

makeReceiverHandshake :: MagicWormhole.SessionKey -> ByteString
makeReceiverHandshake key =
    let hexid = hex $ hkdf salt key purpose
        salt = "" :: ByteString
        purpose = toS @Text @ByteString "transit_receiver"
        hexid' = (toS (toLower (toS @ByteString @Text hexid)))
    in
      (toS @Text @ByteString "transit receiver ") <> hexid' <> (toS @Text @ByteString " ready\n\n")
