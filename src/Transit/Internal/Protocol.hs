{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Transit.Internal.Protocol
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


data AbilityV1
  = DirectTcpV1
  | RelayV1
  deriving (Eq, Show, Generic)

instance ToJSON AbilityV1 where
  toJSON = genericToJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

instance FromJSON AbilityV1 where
  parseJSON = genericParseJSON
    defaultOptions { constructorTagModifier = camelTo2 '-'}

data Hint = Hint { ctype :: AbilityV1
                 , priority :: Double
                 , hostname :: Text
                 , port :: Word16 }
          deriving (Eq, Show, Generic)

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

data ConnectionHint
  = Direct Hint
  | Tor Hint
  | Relay { rtype :: AbilityV1
          , hints :: [Hint] }
  deriving (Eq, Show, Generic)

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

data Ack = FileAck Text
         | MsgAck Text
         deriving (Eq, Show, Generic)

instance ToJSON Ack where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '_'}

instance FromJSON Ack where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = ObjectWithSingleField
                   , constructorTagModifier = camelTo2 '_'}

data Ability = Ability { atype :: AbilityV1 }
  deriving (Eq, Show, Generic)

instance ToJSON Ability where
  toJSON = genericToJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier = const "type" }

instance FromJSON Ability where
  parseJSON = genericParseJSON
    defaultOptions { sumEncoding = UntaggedValue
                   , fieldLabelModifier = const "type" }

data TransitMsg = Error Text
                | Answer Ack
                | Transit { abilitiesV1 :: [Ability]
                          , hintsV1 :: [ConnectionHint] }
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

