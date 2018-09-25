-- | Crypto module tests
module CryptoTests
  ( cryptoRoundTripTests
  ) where

import Protolude

import Hedgehog (forAll, property, (===), failure, Property, Group(..), checkSequential)

import qualified Transit.Internal.Crypto as C
import qualified Crypto.Saltine.Class as Saltine
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import qualified Generator

prop_roundTrip :: Property
prop_roundTrip = property $ do
  purpose <- forAll Generator.purposeGen
  secret <- forAll $ Gen.bytes (Range.singleton 32)
  nonceBytes <- forAll Generator.nonceBytesGen
  let nonce = fromMaybe (panic "cannot decode nonce") $ Saltine.decode nonceBytes
  let secret' = fromMaybe (panic "cannot decode secret") $ Saltine.decode secret
  let key = C.deriveKeyFromPurpose purpose secret'
  let key' = fromMaybe (panic "cannot decode key") $ Saltine.decode key
  plaintext <- forAll $ Gen.bytes (Range.linear 1 256)
  let result = C.encrypt key' nonce (C.PlainText plaintext) >>= C.decrypt key'
  case result of
    Right (pt, _) -> pt === C.PlainText plaintext
    Left _ -> failure

cryptoRoundTripTests :: IO Bool
cryptoRoundTripTests =
  checkSequential $ Group "Crypto"
  [ ("encrypt decrypt roundtrip", prop_roundTrip)
  ]
