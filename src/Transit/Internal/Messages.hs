-- | Description: Client-to-Client messages
-- The JSON messages are derived from these Message types.
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Transit.Internal.Messages
  ( TransitMsg(..)
  , Ability(..)
  , AbilityV1(..)
  , Hint(..)
  , ConnectionHint(..)
  , Ack(..)
  , TransitAck(..)
  ) where

import Protolude

import Data.Aeson
  ( FromJSON(..)
  , ToJSON(..)
  , genericToJSON
  , genericParseJSON
  , defaultOptions
  , fieldLabelModifier
  , constructorTagModifier
  , sumEncoding
  , SumEncoding(..)
  , camelTo2
  )

import qualified Data.Set as Set

-- | Type to represent the abilities
data AbilityV1
  = DirectTcpV1
  -- ^ Can send directly via TCP
  | TorTcpV1
  -- ^ Can send via Tor
  | RelayV1
  -- ^ Can relay via a relay server
  deriving (Eq, Show, Generic)

instance ToJSON AbilityV1 where
  toJSON = genericToJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

instance FromJSON AbilityV1 where
  parseJSON = genericParseJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

-- | Hints are messages that specify ways that the client
-- can connect to the peer.
data Hint = Hint { ctype :: AbilityV1
                 , priority :: Double
                 , hostname :: Text
                 , port :: Word16 }
          deriving (Eq, Show, Generic)

instance Ord Hint where
  Hint _ p1 _ _ `compare` Hint _ p2 _ _ = Down p1 `compare` Down p2

instance ToJSON Hint where
  toJSON = genericToJSON
    defaultOptions { fieldLabelModifier =
                       \name -> case name of
                                  "ctype" -> "type"
                                  _ -> name }

instance FromJSON Hint where
  parseJSON = genericParseJSON
    defaultOptions { fieldLabelModifier =
                       \name -> case name of
                                  "ctype" -> "type"
                                  _ -> name }

-- | Connection Hint is currently a direct hint or a relay hint
data ConnectionHint
  = Direct Hint
    -- ^ Direct Hint
  | Relay { rtype :: AbilityV1
          , hints :: [Hint] }
    -- ^ Relay hint
  deriving (Eq, Show, Generic)

instance Ord ConnectionHint where
  Direct _  `compare` Direct _  = EQ
  Direct _  `compare` Relay _ _ = LT
  Relay _ h1 `compare` Relay _ h2 = h1 `compare` h2
  Relay _ _ `compare` Direct _  = GT

instance ToJSON ConnectionHint where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier =
                       \name -> case name of
                                  "rtype" -> "type"
                                  _ -> name }
instance FromJSON ConnectionHint where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier =
                       \name -> case name of
                                  "rtype" -> "type"
                                  _ -> name }
-- | Ack message type
data Ack = FileAck Text
           -- ^ File Ack
         | MessageAck Text
           -- ^ Message Ack
         deriving (Eq, Show, Generic)

instance ToJSON Ack where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '_'}

instance FromJSON Ack where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '_'}

-- | A newtype specifically for generating Ability JSON messages
newtype Ability = Ability { atype :: AbilityV1 }
  deriving (Eq, Show, Generic)

instance ToJSON Ability where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier = const "type" }

instance FromJSON Ability where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier = const "type" }

-- | Transit, Answer and Error Message from Client to Client
data TransitMsg = Error Text
                | Answer Ack
                  -- ^ Answer message is sent on a successful transfer
                | Transit { abilitiesV1 :: [Ability]
                          , hintsV1 :: Set.Set ConnectionHint }
                  -- ^ Transit message
                deriving (Eq, Show, Generic)

instance ToJSON TransitMsg where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '-'
                   , fieldLabelModifier = camelTo2 '-' }
instance FromJSON TransitMsg where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '-'
                   , fieldLabelModifier = camelTo2 '-'}

-- | Message sent by the receiver of the file to the sender
data TransitAck
  = TransitAck
  { ack :: Text -- ^ "ack" is "ok" implies a successful transfer
  , sha256 :: Text } -- ^ expected sha256 sum of the transfered file
  deriving (Eq, Show, Generic)

instance ToJSON TransitAck where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = UntaggedValue }

instance FromJSON TransitAck where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = UntaggedValue }

