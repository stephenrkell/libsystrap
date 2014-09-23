module GenStructs where

import qualified ParseStructs as PS
import Data.List(intercalate)

data Modifiable = Modifiable_yes | Modifiable_no deriving(Eq)

data CType = Void
           | BasicCType String
           | Array CType String
           | Function CType [(String, CType)] Bool
           | Pointer String String
           | Atomic CType
           | Struct String [(String, Modifiable, CType)]
           | Union  String [(String, Modifiable, CType)]
           deriving(Eq)

data Footprint =
          FPVoid
        | FPBasic String CType
        | FPStruct String CType
        | FPArray String CType String
        | FPSeparationStar [Footprint]
        | FPIndexedSeparationStar String String String Footprint
        | FPZts String
        | FPExtern String String
        deriving (Eq)

genCType :: PS.Struct -> CType
genCType (PS.Struct n fs) = Struct ("struct_" ++ n) (map genField fs)
        where genField (PS.Field n ts) = (n, Modifiable_yes, gct ts)

gct :: [[Char]] -> CType
gct ts | last ts == "*" = Pointer "" $ gpct (init ts)
       | otherwise      = BasicCType (gpct ts)
        where gpct ("struct": x: _)   = "struct_" ++ x
              gpct xs = intercalate " " xs

convertType :: [Char] -> [Char]
convertType "char"  = "Char"
convertType "int"   = "Int"
convertType "long"  = "Long"
convertType "u32"   = "UInt32"
convertType "u64"   = "UInt64"
convertType "__s32" = "Int32"
convertType "__u32" = "UInt32"
convertType s@('s':'t':'r':'u':'c':'t':xs) = s
convertType x       = "Typedef(\"" ++ x ++ "\")"

genStruct :: CType -> String
genStruct (Struct n fs) = n ++ "= Struct(\"" ++ n ++ "\", ["
                                ++ concat (map gf fs) ++ "])"
        where gf (fn, mod, ct) = "(\"" ++ fn ++ "\", " ++ gm mod ++ ", "
                                ++ gct ct ++ ");"
              gm Modifiable_no  = "Modifiable_no"
              gm Modifiable_yes = "Modifiable_yes"
              gct (BasicCType x) = "Basic(" ++ convertType x ++ ")"
              gct (Pointer mods ptype) = "Pointer(\"" ++ mods ++ "\", "
                                        ++ convertType ptype ++ ")"
genStruct _ = undefined

genFootPrintFunc :: PS.Struct -> [String]
genFootPrintFunc (PS.Struct n fs) =
        ("let struct_" ++ n ++ "_footprint " ++ n ++ " = Separation_star([")
      : ("Struct(" ++ n ++ ", struct_" ++ n ++ ");")
      : genSemantics n fs  : ("]);;") : []

genOCamlFootprint :: [PS.Struct] -> String
genOCamlFootprint ss = intercalate "\n" $
                map (\x -> intercalate "\n" $ genFootPrintFunc x) ss

genOCamlStruct :: [PS.Struct] -> String
genOCamlStruct ss = "let " ++ (intercalate "\n and " $
                map (genStruct . genCType) ss)
                ++ ";;"


ct2fp :: String -> CType -> Footprint
ct2fp _ Void = FPVoid
ct2fp _ (BasicCType _) = FPVoid
ct2fp arg (Pointer _ ct) = FPExtern arg ct

cTypeDeref :: CType -> [Char]
cTypeDeref (BasicCType x) = "Basic(" ++ convertType x ++ ")"
cTypeDeref (Pointer _ ptype) = convertType ptype
cTypeDeref _ = undefined

h2oct :: CType -> [Char]
h2oct (BasicCType x) = "Basic(" ++ convertType x ++ ")"
h2oct (Pointer mods ptype) = "Pointer(" ++ mods ++ ", "
                                        ++ convertType ptype ++")"
h2oct _ = undefined

h2ofp :: Footprint -> [Char]
h2ofp FPVoid = "Void;"
h2ofp (FPBasic argn ct) = "Basic(" ++ argn ++ ", "
                                ++ cTypeDeref ct ++ ");"
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

f2fp :: String -> PS.Field -> Footprint
f2fp strn f = let ct = (gct . PS.field_type) f
                  fn = PS.field_name f
              in case ct of
                     Void -> FPVoid
                     BasicCType _ -> FPVoid
                     Pointer "" ptype -> FPBasic ("Member_access(\""
                                                         ++ fn ++ "\")")
                                                 (BasicCType ptype)

genSemantics :: String -> [PS.Field] -> [Char]
genSemantics strn fs = gs strn (filter (/= FPVoid) $ map (f2fp strn) fs)
    where gs _ [] = "Void;"
          gs _ [f] = h2ofp f
          gs _ fs  = "Separation_star(["
                         ++ (concat $ map h2ofp fs) ++ "])"
