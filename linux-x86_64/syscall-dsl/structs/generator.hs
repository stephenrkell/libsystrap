module GenStructs where

import qualified ParseStructs as PS
import Data.List(intercalate)

data Modifiable = Modifiable_yes | Modifiable_no

data CType = Void
           | BasicCType String
           | Array CType String
           | Function CType [(String, CType)] Bool
           | Pointer String String
           | Atomic CType
           | Struct String [(String, Modifiable, CType)]
           | Union  String [(String, Modifiable, CType)]

data Footprint =
          FPVoid
        | FPBasic String CType
        | FPStruct String CType
        | FPArray String CType String
        | FPSeparation_star [Footprint]
        | FPIndexed_separation_star String String String Footprint

genCType :: PS.Struct -> CType
genCType (PS.Struct n fs) = Struct ("struct_" ++ n) (map genField fs)
        where genField (PS.Field n ts) = (n, Modifiable_yes, gct ts)
              gct ts | last ts == "*" = Pointer "" $ gpct (init ts)
                     | otherwise      = BasicCType (intercalate " " ts)
              gpct ("struct":x:_)     = "struct_" ++ x
              gpct xs = intercalate " " xs

genFootPrintFunc :: PS.Struct -> [String]
genFootPrintFunc (PS.Struct n fs) =
        ("let struct_" ++ n ++ "_footprint " ++ n ++ " = Separation_star([")
      : ("Struct(" ++ n ++ ", struct_" ++ n ++ ");")
      : ("... (* FILL ME WITH SEMANTICS *)") : ("]);;") : []

genOCaml :: [PS.Struct] -> String
genOCaml ss = intercalate "\n" $
                map (\x -> intercalate "\n" $ genFootPrintFunc x) ss
