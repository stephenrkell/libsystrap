module Generators where

import Data.List(intercalate, insert, nub)

import Parse

data OCamlStruct = OCS { ocs_name       :: String
                       , ocs_lines      :: [String]
}

c_keywords :: [String]
c_keywords = ["signed", "unsigned", "const", "volatile", "auto", "register", "static", "extern"]
indent :: String
indent = "        "

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
        | FPSeparation_star [Footprint]
        | FPIndexed_separation_star String String String Footprint

genOCamlType :: Argument -> CType
genOCamlType arg =         case (pointer arg, struct arg) of
        (False,_) -> BasicCType $ intercalate " " $ getSimpleType $ arg_type arg
        (_,True)  -> Pointer (if Parse.const arg then "const" else "\"\"")
                                ((structTag . arg_type) arg)
        (_,_)     -> Pointer (if Parse.const arg then "const" else "\"\"") $
                                intercalate " " $ getSimpleType $ arg_type arg

h2o_ctype :: CType -> [Char]
h2o_ctype (BasicCType x) = "Basic(" ++ x ++ ")"
h2o_ctype (Pointer mods ptype) = "Pointer(" ++ mods ++ ", " ++ ptype ++")"
h2o_ctype _ = undefined

genSyscallCopier :: Sys -> [[Char]]
genSyscallCopier sys = ["case SYS_" ++ (sys_name sys) ++ ":"]
                        ++ struct_shape
                        ++ copyArgs (arguments sys)
                        ++ ["break;"]
        where struct_shape = case (length $ arguments sys) of
                0 -> []
                _ -> ("/*") : map (\x -> " * " ++ genArg (snd x) ++ ";")
                                         (arguments sys)
                          ++ [" */"]
              genArg a     = indent ++ (intercalate " " $ arg_type a) ++ " " ++ arg_name a

genOCamlStruct :: Sys -> OCamlStruct
genOCamlStruct sys = let args = arguments sys in
        OCS (sys_name sys) $
        ("let sys_" ++ sys_name sys ++ " = {")          :
        ("name = \"sys_" ++ sys_name sys ++ "\";")      :
        ("number = SYS_" ++ sys_name sys ++ ";")        :
        ["arguments = ["] ++ map genOCamlArgument args ++ ["];"]
        ++ ["footprint = "] ++ footprint args ++ ["}"]

genOCamlArgument :: (Int, Argument) -> [Char]
genOCamlArgument (_, arg) = "(\"" ++ arg_name arg ++ "\", "
                ++ ((h2o_ctype . genOCamlType) arg) ++ ");"

-- TODO
footprint :: [(Int, Argument)] -> [[Char]]
footprint xs = case filter (pointer . snd) xs of
        []      -> ["Void;"]
        [x]     -> [fp x]
        l       -> ["Separation_star(["] ++ map fp l ++ ["]);"]
    where fp (_,arg) =
            if (struct arg)
              then structFootprint arg
            else basicFootprint arg
          basicFootprint arg = "Basic(Argument(" ++ arg_name arg
                ++ "), " ++ (h2o_ctype . genOCamlType) arg ++ ");"
--          structFootprint arg = "Struct(Argument(" ++ arg_name arg
--                ++ "), " ++ (h2o_ctype . genOCamlType) arg ++ ");"
          structFootprint arg = structTag (arg_type arg)
                ++ "_footprint Argument(\"" ++ arg_name arg ++ "\");"

copyArgs :: [(Int, Argument)] -> [[Char]]
copyArgs args = filter (/= []) $ map copyArg args

copyArg :: (Int, Argument) -> [Char]
copyArg (_, arg) = case (pointer arg, struct arg) of
        (True, True)  -> intercalate "\n" $ filter (/= "") [make_copy,
                          copy_struct_if_needed]
        (True, False) -> if is_char_pointer
                                then copy_zts
                                else make_copy
        (_,_)         -> []
        where make_copy = "copy_buf(" ++ (arg_name arg)
                           ++ ", sizeof("
                           ++ (intercalate " "
                                $ getSimpleType $ arg_type arg) ++ "));"
                                ++ " // " ++ (arg_name arg)
              is_char_pointer = "char" `elem` (arg_type arg)
              copy_zts = "unsafe_copy_zts(" ++ arg_name arg ++ ");"
              copy_struct_if_needed =
                let (_:xs) = dropWhile (/=' ') $ head $
                         getSimpleType $ arg_type arg
                    struct_name = xs
                in if struct_name `elem` recursive_copy_structs
                   then "rec_copy_struct(" ++ arg_name arg ++ ");"
                   else if struct_name `elem` no_recursive_copy_structs
                        then ""
                        else "undefined semantics for struct "
                                ++ struct_name

genSwitch :: [Sys] -> [Char]
genSwitch ss = (intercalate "\n" $
                        "switch(syscall_arg[0]) {" :
                        (map (\s ->
                              intercalate "\n" $ genSyscallCopier s) ss))
                        ++ "\n}"

genTab :: [Sys] -> [Char]
genTab ss = "long int (*syscalls[SYSCALL_MAX])(struct generic_syscall *) = {\n"
                ++ (intercalate "\n" $ map decl ss) ++ "\n};"
                where decl s = indent ++ "DECL_SYSCALL(" ++ sys_name s ++ ")"

genTypeList :: [Sys] -> [Char]
genTypeList ss = intercalate "\n" $ nub $ capture_args ss []
        where capture_args [] l         = l
              capture_args (x:xs) l     = capture_args xs
                                         (insert_all_args (map snd $ arguments x) l)
              insert_all_args [] l      = l
              insert_all_args (x:xs) l  = insert_all_args xs
                                        $ insert (intercalate " "
                                        $ getSimpleType ( arg_type x)) l

genOCaml :: [Sys] -> [Char]
genOCaml ss = intercalate "\n" $
                map (\x -> intercalate "\n" $ ocs_lines $
                                                genOCamlStruct x) ss

genStrings :: Sys -> [Char]
genStrings sys = intercalate "\n" $ map (makeLine . snd) $ arguments sys
        where makeLine arg = intercalate " " (arg_type arg) ++ " "
--                ++ arg_name arg


bla :: [Sys] -> [Char]
bla ss = intercalate "\n" $ map genStrings ss

-- Lines that are commented out indicate structs whose internals are
-- unknown at the moment.

recursive_copy_structs :: [String]
recursive_copy_structs = ["__sysctl_args"
--                      , "__old_kernel_stat"
                        , "epoll_event" -- XXX unsure about that one. Being conservative here.
                        , "iovec"
--                      , "file_handle"
--                      , "getcpu_cache"
--                      , "io_event"
--                      , "iocb"
                        , "iovec"
                        , "kexec_segment"
                        , "linux_dirent"
--                      , "linux_dirent64"
--                      "mmap_arg_struct"
                        , "mmsghdr"
--                      , "mq_attr"
                        , "msgbuf"
                        , "msghdr"
--                      , "new_utsname"
--                      , "old_linux_dirent"
--                      , "old_utsname"
--                      , "oldold_utsname"
--                      , "perf_event_attr"
--                      , "rlimit64"
--                      , "robust_list_head"
--                      , "sched_param"
--                      , "sel_arg_struct"
--                      , "sembuf"
--                      , "shmid_ds"
                        , "sigevent"
--                      , "siginfo"
--                      , "stat64"
--                      , "ustat"
                         ]

no_recursive_copy_structs :: [String]
no_recursive_copy_structs = ["ipc_perm"
                           , "itimerspec"
                           , "itimerval"
                           , "msqid_ds"
                           , "pollfd"
                           , "rlimit"
                           , "rusage"
                           , "sockaddr"
                           , "stat"
                           , "statfs"
                           , "sysinfo"
                           , "timespec"
                           , "timeval"
                           , "timex"
                           , "timezone"
                           , "tms"
                           , "utimbuf"
                            ]
