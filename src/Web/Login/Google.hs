{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.Login.Google (validateGoogleLoginToken, GoogleLoginToken (..)) where

import Crypto.JOSE.JWS
import Crypto.JWT
import Data.Proxy
import Data.Text (Text)
import Data.Time.Clock
import Network.HTTP.Req
import Web.Crypto.JWT

googleJwkSet :: IO JWKSet
googleJwkSet = runReq config $ do
  responseBody <$> req GET url NoReqBody (Proxy @(JsonResponse JWKSet)) mempty
  where
    config = defaultHttpConfig
    url = https "www.googleapis.com" /: "oauth2" /: "v3" /: "certs"

newtype GoogleLoginToken = GoogleLoginToken Text

validateGoogleLoginToken :: GoogleLoginToken -> JwtAuthInfo -> IO (Either JWTError ClaimsSet)
validateGoogleLoginToken (GoogleLoginToken jwt) authInfo = do
  set <- googleJwkSet
  verifyJwt set (RawJwt jwt) authInfo

test = do
  now <- getCurrentTime
  print
    =<< validateGoogleLoginToken
      (GoogleLoginToken "abc.123.xyz")
      (JwtAuthInfo "" (["accounts.google.com", "https://accounts.google.com"]))
