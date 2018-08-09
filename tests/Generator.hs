-- | Hedgehog generators for the messages
module Generator
  ( abilityGen
  , abilityV1Gen
  , hintGen
  , connectionHintGen
  , ackGen
  , transitMsgGen
  , transitAckGen
  )
where

import Protolude

import Hedgehog (MonadGen(..))
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import Transit.Internal.Messages
  ( Ability(..)
  , AbilityV1(..)
  , Hint(..)
  , ConnectionHint(..)
  , Ack(..)
  , TransitMsg(..)
  , TransitAck(..)
  )

abilityGen :: MonadGen m => m Ability
abilityGen = Ability <$> abilityV1Gen

abilityV1Gen :: MonadGen m => m AbilityV1
abilityV1Gen = Gen.choice
  [ pure DirectTcpV1
  , pure RelayV1
  ]

hintGen :: MonadGen m => m Hint
hintGen = Hint <$> abilityV1Gen
           <*> Gen.double (Range.linearFrac 0.0 5.0)
           <*> Gen.text (Range.linear 0 100) Gen.unicode
           <*> Gen.word16 (Range.linear 0 maxBound)

connectionHintGen :: MonadGen m => m ConnectionHint
connectionHintGen = Gen.choice
  [ Direct <$> hintGen
  , Relay <$> abilityV1Gen <*> Gen.list (Range.linear 0 10) hintGen
  ]

ackGen :: MonadGen m => m Ack
ackGen = Gen.choice
  [ FileAck <$> Gen.text (Range.linear 0 100) Gen.ascii
  , MessageAck <$> Gen.text (Range.linear 0 100) Gen.ascii
  ]

transitMsgGen :: MonadGen m => m TransitMsg
transitMsgGen = Gen.choice
  [ Error <$> Gen.text (Range.linear 0 100) Gen.unicode
  , Answer <$> ackGen
  , Transit
    <$> Gen.list (Range.linear 0 5) abilityGen
    <*> Gen.list (Range.linear 0 5) connectionHintGen
  ]

transitAckGen :: MonadGen m => m TransitAck
transitAckGen = TransitAck
  <$> Gen.text (Range.linear 0 5) Gen.unicode
  <*> Gen.text (Range.singleton 64) Gen.hexit
