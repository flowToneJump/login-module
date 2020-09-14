{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Web.Login.Password (authenticate, loginHandler, LoginRequest (..), LoginApi (..), HashedPassword (..)) where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant (Handler, JSON, Post, ReqBody, (:>))
import Web.Crypto (ValidationError, hashValidation)

type LoginApi = "login" :> ReqBody '[JSON] LoginRequest :> Post '[JSON] Bool

-- | A request from the user to login
data LoginRequest = LoginRequest {userId :: Text, password :: Text} deriving (Generic)

instance FromJSON LoginRequest

instance ToJSON LoginRequest

-- | A hashed password, probably stored in a database
newtype HashedPassword = MkHashedPassword Text

-- | Authenticate a password against a stored hash
authenticate ::
  (MonadIO m) =>
  -- | Means to retrieve hashed password
  (Text -> m (Maybe HashedPassword)) ->
  LoginRequest ->
  m (Either ValidationError Bool)
authenticate getHashedPass (LoginRequest userId pass) = do
  getHashedPass userId >>= \case
    Just (MkHashedPassword hash) -> pure $ hashValidation pass hash
    Nothing -> error "Not handling failed authentication"

-- | Handle the login paths
loginHandler ::
  -- | Means to retrieve hashed password
  (Text -> IO (Maybe HashedPassword)) ->
  LoginRequest ->
  Handler Bool
loginHandler lookupHashedPass r = do
  liftIO (authenticate lookupHashedPass r) >>= \case
    Right b -> pure b
    Left e -> error "Not handling failed authentication"
