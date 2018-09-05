-- | Crypto module tests
module CryptoTests
  ( cryptoRoundTripTests
  ) where

import Protolude

import Hedgehog (forAll, property, (===))

import qualified Transit.Internal.Crypto as C
import qualified Crypto.Saltine.Class as Saltine
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import Hedgehog (Property, Group(..), checkSequential)

prop_roundTripWithZeroNonce :: C.Purpose -> Property
prop_roundTripWithZeroNonce purpose = property $ do
  secret <- forAll $ Gen.bytes (Range.singleton 32)
  let nonce = Saltine.zero
  let secret' = fromMaybe (panic "cannot decode secret") $ Saltine.decode secret
  let key = C.deriveKeyFromPurpose purpose secret'
  let key' = fromMaybe (panic "cannot decode key") $ Saltine.decode key
  plaintext <- forAll $ Gen.bytes (Range.linear 1 256)
  let (Right (pt, _))  = C.encrypt key' nonce (C.PlainText plaintext) >>=
                        C.decrypt key'
  pt === C.PlainText plaintext

prop_roundTripWithNonZeroNonce :: C.Purpose -> Property
prop_roundTripWithNonZeroNonce purpose = property $ do
  secret <- forAll $ Gen.bytes (Range.singleton 32)
  let nonce = Saltine.nudge Saltine.zero
  let secret' = fromMaybe (panic "cannot decode secret") $ Saltine.decode secret
  let key = C.deriveKeyFromPurpose purpose secret'
  let key' = fromMaybe (panic "cannot decode key") $ Saltine.decode key
  plaintext <- forAll $ Gen.bytes (Range.linear 1 256)
  let (Right (pt, _))  = C.encrypt key' nonce (C.PlainText plaintext) >>=
                        C.decrypt key'
  pt === C.PlainText plaintext

cryptoRoundTripTests :: IO Bool
cryptoRoundTripTests =
  checkSequential $ Group "Crypto"
  [ ("sender handshake roundtrip with zero nonce", prop_roundTripWithZeroNonce C.SenderHandshake)
  , ("sender handshake roundtrip with non-zero nonce", prop_roundTripWithNonZeroNonce C.SenderHandshake)
  , ("receiver record roundtrip with zero nonce", prop_roundTripWithZeroNonce C.ReceiverRecord)
  , ("receiver record roundtrip with non-zero nonce", prop_roundTripWithNonZeroNonce C.ReceiverRecord)
  , ("sender record roundtrip with zero nonce", prop_roundTripWithZeroNonce C.SenderRecord)
  , ("sender record roundtrip with non-zero nonce", prop_roundTripWithNonZeroNonce C.SenderRecord)
  , ("relay handshake roundtrip with zero nonce", prop_roundTripWithZeroNonce C.RelayHandshake)
  , ("sender record roundtrip with non-zero nonce", prop_roundTripWithNonZeroNonce C.RelayHandshake)
  ]
