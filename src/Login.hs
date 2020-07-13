{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Login (loginHandler, LoginAPI (..), HashedPassword (..)) where

import Control.Monad.IO.Class
import Crypto
import Data.Aeson
import Data.Text
import GHC.Generics
import Network.Wai
import Servant

type LoginAPI = "login" :> ReqBody '[JSON] LoginRequest :> Post '[JSON] Bool

-- | A request from the user to login
data LoginRequest = LoginRequest {userId :: Text, password :: Text} deriving (Generic)

instance FromJSON LoginRequest

-- | A hashed password, probably stored in a database
newtype HashedPassword = MkHashedPassword Text

authenticate :: (MonadIO m) => (Text -> m (Maybe HashedPassword)) -> LoginRequest -> m (Either ValidationError Bool)
authenticate getHashedPass (LoginRequest userId pass) = do
  getHashedPass userId >>= \case
    Just (MkHashedPassword hash) -> pure $ hashValidation pass hash
    Nothing -> error "Not handling failed authentication"

loginHandler :: (Text -> IO (Maybe HashedPassword)) -> LoginRequest -> Handler Bool
loginHandler lookupHashedPass r = do
  liftIO (authenticate lookupHashedPass r) >>= \case
    Right b -> pure b
    Left e -> error "Not handling failed authentication"
