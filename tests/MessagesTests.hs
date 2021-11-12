{-# LANGUAGE OverloadedStrings #-}
module MessagesTests
  ( messagesRoundTripTests
  )
where

import Protolude hiding (toS)

import Data.Aeson
  ( encode
  , eitherDecode
  )
import Hedgehog (forAll, property, Property, Group(..), checkSequential, tripping)
import qualified Generator

prop_abilityTrip :: Property
prop_abilityTrip = property $ do
  x <- forAll Generator.abilityGen
  tripping x encode eitherDecode

prop_hintTrip :: Property
prop_hintTrip = property $ do
  x <- forAll Generator.hintGen
  tripping x encode eitherDecode

prop_connectionHintTrip :: Property
prop_connectionHintTrip = property $ do
  x <- forAll Generator.connectionHintGen
  tripping x encode eitherDecode

prop_ackTrip :: Property
prop_ackTrip = property $ do
  x <- forAll Generator.ackGen
  tripping x encode eitherDecode

prop_transitMsgTrip :: Property
prop_transitMsgTrip = property $ do
  x <- forAll Generator.transitMsgGen
  tripping x encode eitherDecode

prop_transitAckTrip :: Property
prop_transitAckTrip = property $ do
  x <- forAll Generator.transitAckGen
  tripping x encode eitherDecode

messagesRoundTripTests :: IO Bool
messagesRoundTripTests =
  checkSequential $ Group "Messages"
  [ ("prop_abilityTrip", prop_abilityTrip)
  , ("prop_hintTrip", prop_hintTrip)
  , ("prop_connectionHintTrip", prop_connectionHintTrip)
  , ("prop_ackTrip", prop_ackTrip)
  , ("prop_transitMsgTrip", prop_transitMsgTrip)
  , ("prop_transitAckTrip", prop_transitAckTrip)
  ]

