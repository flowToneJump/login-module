{-# LANGUAGE OverloadedStrings #-}

import Crypto
import Data.Either (isLeft)
import Data.Text (Text)
import Test.Hspec

main :: IO ()
main = hspec $ do
  describe "Lib.saltedHash" $ do
    it "Outputs different text from input" $ do
      let pass = "HelloThere"
      result <- saltedHash pass
      result `shouldNotBe` pass

    it "Salts passwords" $ do
      let pass = "HelloThere"
      first <- saltedHash pass
      second <- saltedHash pass
      first `shouldNotBe` second

  describe "Lib.hashValidation" $ do
    it "Accepts associated hash" $ do
      let pass = "HelloThere"
      hashed <- saltedHash pass
      hashValidation pass hashed `shouldBe` Right True

    it "Rejects non-associated hash" $ do
      let pass = "HelloThere"
      let other = "Wrong"
      hashed <- saltedHash other
      hashValidation pass hashed `shouldBe` Right False

    it "Returns error on invalid format" $ do
      let pass = "HelloThere"
      let hashed = "Wrong"
      hashValidation pass hashed `shouldSatisfy` isLeft
