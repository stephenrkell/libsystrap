module Generators where

import Data.List(intercalate, insert, nub)

import Parse

data OCamlStruct = OCS { ocs_name       :: String
                       , ocs_lines      :: [String]
}

c_keywords :: [String]
c_keywords = ["signed", "unsigned", "const", "volatile", "auto", "register", "static", "extern"]

fusionStruct :: [[Char]] -> [Char] -> [[Char]]
fusionStruct (x:y:xs) inter | x == "struct" =
                                (x ++ inter ++ y)       : fusionStruct xs inter
fusionStruct (x:xs) inter = x           : fusionStruct xs inter
fusionStruct x _ = x

getSimpleType :: [[Char]] -> [[Char]]
getSimpleType args = filter (\x -> notElem x $ "__user" : "*" : c_keywords)
                        $ fusionStruct args " "

structTag :: [[Char]] -> [Char]
structTag (x:y:xs) | x == "struct" = x ++ "_" ++ y
                   | otherwise     = structTag (y:xs)
structTag _ = []

data CType = Void
           | BasicCType String
           | Array CType String
           | Function CType [(String, CType)] Bool
           | Pointer String String
           | Atomic CType
           | Struct String [(String, String, CType)]
           | Union String [(String, String, CType)]

data Footprint =
          FPVoid
        | FPBasic String CType
        | FPStruct String CType
        | FPArray String CType String
        | FPSeparationStar [Footprint]
        | FPIndexedSeparationStar String String String Footprint
        | FPZts String
        | FPExtern String String

genOCamlType :: Argument -> CType
genOCamlType arg = case (pointer arg, struct arg) of
        (False,_) -> BasicCType $ intercalate " " $ getSimpleType $ arg_type arg
        (_,True)  -> Pointer (if Parse.const arg then "\"const\"" else "\"\"")
                                ((structTag . arg_type) arg)
        (_,_)     -> Pointer (if Parse.const arg then "\"const\"" else "\"\"") $
                                intercalate " " $ getSimpleType $ arg_type arg

convertType :: [Char] -> [Char]
convertType "char"  = "Char"
convertType "int"   = "Int"
convertType "long"  = "Long"
convertType "u32"   = "UInt32"
convertType "u64"   = "UInt64"
convertType "__s32" = "Int32"
convertType "__u32" = "UInt32"
convertType x       = "Typedef(\"" ++ x ++ "\")"

h2oct :: CType -> [Char]
h2oct (BasicCType x) = "Basic(" ++ convertType x ++ ")"
h2oct (Pointer mods ptype) = "Pointer(" ++ mods ++ ", "
                                        ++ convertType ptype ++")"
h2oct _ = undefined

cTypeDeref :: CType -> [Char]
cTypeDeref (BasicCType x) = "Basic(" ++ x ++ ")"
cTypeDeref (Pointer _ ptype) = ptype
cTypeDeref _ = undefined

genOCamlStruct :: Sys -> OCamlStruct
genOCamlStruct sys = let args = arguments sys in
        OCS (sys_name sys) $
        ("let sys_" ++ sys_name sys ++ " = {")          :
        ("name = \"sys_" ++ sys_name sys ++ "\";")      :
        ("number = \"SYS_" ++ sys_name sys ++ "\";")        :
        ["arguments = ["] ++ map genOCamlArgument args ++ ["];"]
        ++ ["footprint = "]
        ++ [ h2ofp $ filterFootprint (sys_name sys) args] ++ ["}"]

genOCamlArgument :: Argument -> [Char]
genOCamlArgument arg = "(\"" ++ arg_name arg ++ "\", "
                ++ ((h2oct . genOCamlType) arg) ++ ");"

fpOfArgs :: [Argument] -> Footprint
fpOfArgs args = case filter pointer args of
        []  -> FPVoid
        [x] -> fp x
        l   -> FPSeparationStar $ map fp l
    where fp arg | struct arg = sfp arg
                 | otherwise  = bfp arg
          bfp arg = FPBasic (fmt arg)
                                (genOCamlType arg)
          sfp arg = FPExtern (structTag (arg_type arg) ++ "_footprint")
                                (fmt arg)
          fmt arg = "Argument(\"" ++ arg_name arg ++ "\")"

h2ofp :: Footprint -> [Char]
h2ofp FPVoid = "Void;"
h2ofp (FPBasic argn ct) = "Basic(" ++ argn ++ ", "
                                ++ (convertType . cTypeDeref) ct ++ ");"
h2ofp (FPSeparationStar l) = "Separation_star(["
                                ++ (concat $ map h2ofp l) ++ "]);"
h2ofp (FPArray argn ct sz) = "Array(" ++ argn ++ ", "
                                ++ h2oct ct ++ ", " ++ sz ++ ");"
h2ofp (FPIndexedSeparationStar s1 s2 s3 fp) = "Indexed_separation_star("
                ++ s1 ++ ", "
                ++ s2 ++ ", "
                ++ s3 ++ ", "
                ++ h2ofp fp ++ ");"
h2ofp (FPExtern ffp argn) = ffp ++ " " ++ argn ++ ";"
h2ofp (FPZts lv) = "Zts(" ++ lv ++ ");"
h2ofp _ = undefined

genTypeList :: [Sys] -> [Char]
genTypeList ss = intercalate "\n" $ nub $ capture_args ss []
        where capture_args [] l         = l
              capture_args (x:xs) l     = capture_args xs
                                         (insert_all_args (arguments x) l)
              insert_all_args [] l      = l
              insert_all_args (x:xs) l  = insert_all_args xs
                                        $ insert (intercalate " "
                                        $ getSimpleType ( arg_type x)) l

genOCaml :: [Sys] -> [Char]
genOCaml ss = intercalate "\n" $
                map (\x -> intercalate "\n" $ ocs_lines $
                                                genOCamlStruct x) ss

accessArg :: [Argument] -> Int -> [Char]
accessArg args n = "Argument(\"" ++ arg_name (args !! n) ++ "\")"

filterFootprint :: [Char] -> [Argument] -> Footprint
filterFootprint "getgroups" args = FPArray (accessArg args 1)
                                             (BasicCType "gid_t")
                                             (accessArg args 0)
filterFootprint "write" args = FPArray (accessArg args 1)
                                        (BasicCType "char")
                                        (accessArg args 2)
filterFootprint "read" args = FPArray (accessArg args 1)
                                        (BasicCType "char")
                                        (accessArg args 2)
filterFootprint _ args = fpOfArgs args
