module Transit.Internal.Errors
  (
    -- * Error
    CommunicationError(..)
  )
where

import Protolude

data CommunicationError
  = ConnectionError Text
  -- ^ We could not establish a socket connection.
  | OfferError Text
  -- ^ Clients could not exchange offer message.
  | TransitError Text
  -- ^ There was an error in transit protocol exchanges.
  | Sha256SumError Text
  -- ^ Sender got back a wrong sha256sum from the receiver.
  | UnknownPeerMessage Text
  -- ^ We could not identify the message from peer.
  | BadNonce Text
  -- ^ The nonce value in the received message is invalid.
  | CouldNotDecrypt Text
  -- ^ We could not decrypt the incoming encrypted record.
  deriving (Eq, Show)

instance Exception CommunicationError

