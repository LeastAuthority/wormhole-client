{-# LANGUAGE OverloadedStrings #-}
module FileTransfer.Internal.Messages
  ( makeSenderHandshake
  )
where

import Protolude
import MagicWormhole

import qualified Crypto.KDF.HKDF as HKDF
import Crypto.Hash (SHA256(..))
import qualified Crypto.Saltine.Internal.ByteSizes as ByteSizes
import Data.Hex (hex)
import Data.Text (toLower)

makeSenderHandshake :: MagicWormhole.SessionKey -> ByteString
makeSenderHandshake (MagicWormhole.SessionKey key) =
    let hexid = (HKDF.expand (HKDF.extract salt key :: HKDF.PRK SHA256) purpose keySize)
        salt = "" :: ByteString
        keySize = ByteSizes.secretBoxKey
        purpose = toS @Text @ByteString "transit_sender"
    in
      (toS @Text @ByteString "transit sender ") <> (hex hexid) <> (toS @Text @ByteString " ready\n\n")
