{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Auth where

import Control.Monad.IO.Class
import Data.ByteString (ByteString)
import Data.Proxy
import Data.Text
import Network.Wai (Request, requestHeaders)
import Servant (AuthProtect, Handler, err401, err403, errBody, throwError, (:<|>), (:>))
import Servant.Server.Experimental.Auth
import Servant.Server.Internal.Handler
import Web.Cookie (parseCookies)

type instance AuthServerData (AuthProtect "cookie-auth") = Session

-- | API with auth-protection
type AuthAPI private public =
  "private" :> AuthProtect "cookie-auth" :> private
    :<|> "public" :> public

-- | User session
newtype Session = Session ByteString

-- | A handler for authenticated APIs
authHandler ::
  -- | The means to lookup the user's session
  (ByteString -> IO (Maybe Session)) ->
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
          liftIO (sessionLookup t) >>= \case
            Just s -> pure s
            Nothing -> throwError (err403 {errBody = "Invalid Cookie"})

    maybeToEither e = maybe (Left e) Right

    throw401 msg = throwError $ err401 {errBody = msg}

    getToken req = do
      -- Get token from request body
      cookie <- maybeToEither "Missing cookie header" . lookup "cookie" $ requestHeaders req
      maybeToEither "Missing token in cookie" . lookup sessCookieName $ parseCookies cookie
