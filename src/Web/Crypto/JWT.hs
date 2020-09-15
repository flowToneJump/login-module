{-# LANGUAGE OverloadedStrings #-}

module Web.Crypto.JWT where

import Control.Monad
import Data.ByteString (ByteString)
import Data.Text
import Web.JWT
import qualified Web.JWT as JWT

data JwtValidationError
  = PemParsingError
  | TooManyPem
  | NoPemParsed
  | CouldNotParseJwt
  | InvalidJwt
  | InvalidAud
  | InvalidIss
  | Expired

newtype RawPem = RawPem ByteString

newtype RawJwt = RawJwt Text

data GoogleAuthInfo = GoogleAuthInfo
  { appClientId :: StringOrURI,
    validIssOpts :: [StringOrURI],
    currTime :: NumericDate
  }

verifyJwt :: RawPem -> RawJwt -> GoogleAuthInfo -> Either JwtValidationError (JWT VerifiedJWT)
verifyJwt (RawPem rawPem) (RawJwt rawJwt) authInfo = do
  pem <- maybe (Left PemParsingError) pure $ readRsaSecret rawPem
  unverifiedJwt <- maybe (Left CouldNotParseJwt) pure $ decode rawJwt
  jwt <- maybe (Left InvalidJwt) pure $ verify (RSAPrivateKey pem) unverifiedJwt
  unless (validAud jwt) $ Left InvalidAud
  unless (validIss jwt) $ Left InvalidIss
  unless (not $ expired jwt) $ Left InvalidIss
  pure jwt
  where
    validAud = maybe False (elem (appClientId authInfo) . either pure id) . aud . claims
    validIss = maybe False (flip elem (validIssOpts authInfo)) . iss . claims
    expired = maybe False (currTime authInfo <=) . JWT.exp . claims
