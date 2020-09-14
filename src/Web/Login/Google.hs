module Web.Login.Google (validateGoogleLoginToken, GoogleLoginToken (..)) where

import Data.ByteString
import Data.Text
import Web.Crypto.JWT

googlePem :: IO ByteString
googlePem = undefined

newtype GoogleLoginToken = GoogleLoginToken Text

validateGoogleLoginToken :: GoogleLoginToken -> IO (Either JwtValidationError ())
validateGoogleLoginToken (GoogleLoginToken jwt) = do
  pem <- googlePem
  pure $ () <$ verifyJwt (RawPem pem) (RawJwt jwt)
