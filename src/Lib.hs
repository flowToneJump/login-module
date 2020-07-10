{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Lib
  ( saltedHash,
    hashValidation,
    ValidationErrorType (..),
    ValidationError (..),
  )
where

import qualified Crypto.KDF.BCrypt as BCrypt
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.List (isPrefixOf)
import Data.String.Conv (toS)
import Data.Text (Text)

-- | Generate a salted hash for a given text input
saltedHash ::
  -- | Text to hash
  Text ->
  IO Text
saltedHash = fmap (toS @ByteString) . BCrypt.hashPassword 12 . toS @_ @ByteString

-- | Possible outcomes of `hashValidation`
data ValidationErrorType
  = InvalidHashFormat
  | UnsupportedVersion
  | InvalidCost
  | UnknownError
  deriving (Show, Eq)

newtype ValidationError
  = MkValidationError (ValidationErrorType, String)
  deriving (Show, Eq)

-- | Validate the given text input against a hash
hashValidation ::
  -- | Candidate original text
  Text ->
  -- | Hash of original text
  Text ->
  Either ValidationError Bool
hashValidation password hashed = first wrapError $ BCrypt.validatePasswordEither password' hashed'
  where
    password' = toS @_ @ByteString password
    hashed' = toS @_ @ByteString hashed
    wrapError str = MkValidationError (errorType str, str)
    errorType str
      | "Invalid hash" `isPrefixOf` str = InvalidHashFormat
      | "Unsupported" `isPrefixOf` str = UnsupportedVersion
      | "Invalid by" `isPrefixOf` str = InvalidCost
      | otherwise = UnknownError
