{-# LANGUAGE NoMonomorphismRestriction #-}

module Parse where

import Text.ParserCombinators.Parsec
import Control.Monad(liftM)
import Data.List(intercalate)

-- The structure that we are meaning to parse looks like this:
-- GENTYPE sys_NAME(arg1,
--                  arg2,
--                  …
--                  argn);

data Gentype = Auto | Stub | None deriving (Show)

data Mutability = Simple | Const | Mut deriving (Show)

data Argument = Argument {mut     :: Mutability
                         ,argtype :: String
                         ,argname :: String
                         } deriving (Show)

data Sys = Sys {gentype  :: Gentype
               ,sys_name :: String
               ,args     :: [Argument]
               } deriving (Show)

-- XXX Obviously this accepts invalid C symbols, but fixing it is low priority.
c_symbol = many1 $ try alphaNum <|> char '_'

file = endBy line (try (string ";\n") <|> try (string ";"))

line = do gt <- parseGentype
          spaces
          string "sys_"
          name <- c_symbol
          spaces
          void <- option [] $ try $ string "(void)"
          case void of
                "(void)" -> return $ Sys gt name []
                _        -> do args <- between (char '(') (char ')') parseArgs
                               return $ Sys gt name args

parseArgs = sepBy parseArg (string ",\n")

parseArg = do my_mut  <- parseMutable
              spaces
              my_type <- liftM (intercalate " ") $
                                many1 $ try $ c_symbol >>=
                                    \x -> (many1 space) >> return x
              star    <- option "" $ try (string "*")
              my_name <- c_symbol
              return $ Argument my_mut (my_type ++ star) my_name

parseGentype = liftM choose $ many1 upper
        where choose = \x -> case x of
                                "AUTO" -> Auto
                                "STUB" -> Stub
                                "NONE" -> None

parseMutable = liftM choose $ option "simple" (try (string "mut")
                                           <|> try (string "const"))
        where choose = \x -> case x of
                                        "simple" -> Simple
                                        "mut"    -> Mut
                                        "const"  -> Const

parseFile = parse file "(unknown)"
