{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.Login.Google (validateGoogleLoginToken, GoogleLoginToken (..)) where

import Data.ByteString
import Data.Text
import Network.HTTP.Req
import Web.Crypto.JWT

googlePem :: IO ByteString
googlePem = runReq config $ do
  responseBody <$> req GET url NoReqBody bsResponse mempty
  where
    config = defaultHttpConfig
    url = https "www.googleapis.com" /: "oauth2" /: "v1" /: "certs"

newtype GoogleLoginToken = GoogleLoginToken Text

validateGoogleLoginToken :: GoogleLoginToken -> GoogleAuthInfo -> IO (Either JwtValidationError ())
validateGoogleLoginToken (GoogleLoginToken jwt) authInfo = do
  pem <- googlePem
  pure $ () <$ verifyJwt (RawPem pem) (RawJwt jwt) authInfo
