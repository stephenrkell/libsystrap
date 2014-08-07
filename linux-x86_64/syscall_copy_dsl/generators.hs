module Generators where

import Data.List(intercalate, insert, nub)

import Parse

c_keywords :: [String]
c_keywords = ["signed", "unsigned", "const", "volatile", "auto", "register", "static", "extern"]
indent :: String
indent = "        "

fusionStruct :: [[Char]] -> [[Char]]
fusionStruct (x:y:xs) | x == "struct" = (x ++ " " ++ y) : fusionStruct xs
fusionStruct (x:xs)                   = x        : fusionStruct xs
fusionStruct x = x

getSimpleType :: [[Char]] -> [[Char]]
getSimpleType args = filter (\x -> notElem x $ "__user" : "*" : c_keywords)
                        $ fusionStruct args

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

copyArgs :: [(Int, Argument)] -> [[Char]]
copyArgs args = filter (/= []) $ map copyArg args

copyArg :: (Int, Argument) -> [Char]
copyArg arg = case (pointer (snd arg), struct (snd arg)) of
        (True, True)  -> intercalate "\n" $ filter (/= "") [make_copy arg,
                          copy_struct_if_needed (snd arg)]
        (True, False) -> if is_char_pointer
                                then copy_string (fst arg)
                                else make_copy arg
        (_,_)         -> []
        where make_copy a = "copy_buf(syscall_arg[" ++ (show $ fst a) ++ "]"
                           ++ ", sizeof("
                           ++ (intercalate " "
                                $ getSimpleType $ arg_type (snd a)) ++ "));"
                                ++ " // " ++ (arg_name $ snd a)
              is_char_pointer = "char" `elem` (arg_type (snd arg))
              copy_string n = "unsafe_copy_zts(syscall_arg[" ++ show n ++ "]);"
              copy_struct_if_needed a =
                let (_:xs) = dropWhile (/=' ') $ head $ getSimpleType $ arg_type a
                    struct_name = xs
                in if struct_name `elem` recursive_copy_structs
                   then "rec_copy_struct(" ++ arg_name a ++ ");"
                   else if struct_name `elem` no_recursive_copy_structs
                        then ""
                        else "undefined semantics for struct " ++ struct_name

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
