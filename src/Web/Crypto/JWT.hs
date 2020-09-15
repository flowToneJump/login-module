{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.Crypto.JWT where

import Control.Lens
import Control.Monad.Except
import Crypto.JOSE.Compact
import Crypto.JOSE.JWK
import Crypto.JWT
import Data.String.Conv
import Data.Text (Text)

newtype RawJwt = RawJwt Text

data JwtAuthInfo = JwtAuthInfo
  { appClientId :: StringOrURI,
    validIssOpts :: [StringOrURI]
  }

verifyJwt :: JWKSet -> RawJwt -> JwtAuthInfo -> IO (Either JWTError ClaimsSet)
verifyJwt jwkSet (RawJwt rawJwt) authInfo = runExceptT $ do
  unverifiedJwt <- decodeCompact (toSL rawJwt)
  verifyClaims config jwkSet unverifiedJwt
  where
    config :: JWTValidationSettings
    config =
      defaultJWTValidationSettings (appClientId authInfo ==)
        & jwtValidationSettingsIssuerPredicate .~ (flip elem (validIssOpts authInfo))
