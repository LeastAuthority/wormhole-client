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

prop_cryptoRoundTripWithZeroNonce :: Property
prop_cryptoRoundTripWithZeroNonce = property $ do
  secret <- forAll $ Gen.bytes (Range.singleton 32)
  let nonce = Saltine.zero
  let secret' = fromMaybe (panic "cannot decode secret") $ Saltine.decode secret
  let key = C.deriveKeyFromPurpose C.SenderHandshake secret'
  let key' = fromMaybe (panic "cannot decode key") $ Saltine.decode key
  plaintext <- forAll $ Gen.bytes (Range.linear 1 256)
  let (Right (pt, _))  = C.encrypt key' nonce (C.PlainText plaintext) >>=
                        C.decrypt key'
  pt === C.PlainText plaintext

prop_cryptoRoundTripWithNonZeroNonce :: Property
prop_cryptoRoundTripWithNonZeroNonce = property $ do
  secret <- forAll $ Gen.bytes (Range.singleton 32)
  let nonce = Saltine.nudge Saltine.zero
  let secret' = fromMaybe (panic "cannot decode secret") $ Saltine.decode secret
  let key = C.deriveKeyFromPurpose C.SenderHandshake secret'
  let key' = fromMaybe (panic "cannot decode key") $ Saltine.decode key
  plaintext <- forAll $ Gen.bytes (Range.linear 1 256)
  let (Right (pt, _))  = C.encrypt key' nonce (C.PlainText plaintext) >>=
                        C.decrypt key'
  pt === C.PlainText plaintext

cryptoRoundTripTests :: IO Bool
cryptoRoundTripTests =
  checkSequential $ Group "Crypto"
  [ ("prop_cryptoRoundTripWithZeroNonce", prop_cryptoRoundTripWithZeroNonce)
  , ("prop_cryptoRoundTripWithNonZeroNonce", prop_cryptoRoundTripWithNonZeroNonce)
  ]
