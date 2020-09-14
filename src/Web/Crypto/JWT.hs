module Web.Crypto.JWT where

import Data.ByteString
import Data.Text
import Web.JWT

data JwtValidationError
  = PemParsingError
  | TooManyPem
  | NoPemParsed
  | CouldNotParseJwt
  | InvalidJwt

newtype RawPem = RawPem ByteString

newtype RawJwt = RawJwt Text

verifyJwt :: RawPem -> RawJwt -> Either JwtValidationError (JWT VerifiedJWT)
verifyJwt (RawPem rawPem) (RawJwt rawJwt) = do
  pem <- maybe (Left PemParsingError) pure $ readRsaSecret rawPem
  unverifiedJwt <- maybe (Left CouldNotParseJwt) pure $ decode rawJwt
  maybe (Left InvalidJwt) pure $ verify (RSAPrivateKey pem) unverifiedJwt
