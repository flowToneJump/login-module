{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Web.Auth (authHandler, Session (..), AuthApi) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.Wai (Request, requestHeaders)
import Servant (AuthProtect, Handler, JSON, Post, ReqBody, err401, err403, errBody, throwError, (:<|>), (:>))
import Servant.Foreign (HasForeign (..), Req)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)
import Web.Cookie (parseCookies)

type instance AuthServerData (AuthProtect "cookie-auth") = Session

type PasswordManagementApi = ReqBody '[JSON] PasswordUpdate :> Post '[JSON] Bool

-- | API with auth-protection
type AuthApi private public =
  "private" :> AuthProtect "cookie-auth" :> (PasswordManagementApi :<|> private)
    :<|> public

instance HasForeign lang ty (AuthProtect "cookie-auth") where
  type Foreign ty (AuthProtect "cookie-auth") = Session -> Req ty
  foreignFor lang ty Proxy sess = error "Undefined foreignFor for AuthProtect"

-- | User session
newtype Session = MkSession ByteString

data PasswordUpdate = MkPasswordUpdate
  { passUpdateUserId :: Text,
    passUpdateOldPass :: Text,
    passUpdateNewPass :: Text
  }
  deriving (Generic)

instance FromJSON PasswordUpdate

instance ToJSON PasswordUpdate

-- | A handler for authenticated Apis
authHandler ::
  -- | The means to lookup the user's session
  (Session -> IO (Maybe Session)) ->
  -- | Name of session cookie
  ByteString ->
  AuthHandler Request Session
authHandler sessionLookup sessCookieName = mkAuthHandler handler
  where
    handler :: Request -> Handler Session
    handler req = do
      case getToken req of
        Left msg -> throw401 msg
        Right t -> do
          -- Check if session exists
          liftIO (sessionLookup . MkSession $ t) >>= \case
            Just s -> pure s
            Nothing -> throwError (err403 {errBody = "Invalid Cookie"})

    maybeToEither e = maybe (Left e) Right

    throw401 msg = throwError $ err401 {errBody = msg}

    getToken req = do
      -- Get token from request body
      cookie <- maybeToEither "Missing cookie header" . lookup "cookie" $ requestHeaders req
      maybeToEither "Missing token in cookie" . lookup sessCookieName $ parseCookies cookie
