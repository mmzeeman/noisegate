%% Settings parsing for the distribution carrier.
-module(noisegate_settings).

-export([parse/0, parse/1, parse/3, parse/4, read_optfile/1]).

-spec parse() -> {ok, map()} | {error, term()}.
parse() ->
    parse(#{}).

-spec parse(map()) -> {ok, map()} | {error, term()}.
parse(Opts) when is_map(Opts) ->
    Flags = argument_settings(),
    Env = environment_settings(),
    case optfile_settings(Opts, Flags, Env) of
        {ok, File} ->
            parse(Opts, Flags, Env, File);
        {error, _} = Error ->
            Error
    end;
parse(_) ->
    {error, bad_options}.

-spec parse(map(), map(), map()) -> {ok, map()} | {error, term()}.
parse(Opts, Flags, Env)
  when is_map(Opts), is_map(Flags), is_map(Env) ->
    parse(Opts, Flags, Env, #{});
parse(_, _, _) ->
    {error, bad_options}.

%% The fourth layer holds the settings of a `-noisegate_optfile` config file
%% (string keys), with the lowest precedence above the defaults.
-spec parse(map(), map(), map(), map()) -> {ok, map()} | {error, term()}.
parse(Opts, Flags, Env, File)
  when is_map(Opts), is_map(Flags), is_map(Env), is_map(File) ->
    Layers = [policy_layer(Opts), policy_layer(Flags), policy_layer(Env),
              policy_layer(File)],
    case {noisegate_protocol:sender_policy(Layers),
          noisegate_protocol:receiver_policy(Layers),
          carrier_values(Opts, Flags, Env, File)}
    of
        {{ok, SenderPolicy}, {ok, ReceiverPolicy}, {ok, Carrier}} ->
            {ok, Carrier#{sender_policy => SenderPolicy,
                          receiver_policy => ReceiverPolicy}};
        {{error, Reason}, _, _} -> {error, Reason};
        {_, {error, Reason}, _} -> {error, Reason};
        {_, _, {error, _} = Error} -> Error
    end;
parse(_, _, _, _) ->
    {error, bad_options}.

carrier_values(Opts, Flags, Env, File) ->
    Values = [{handshake_timeout_ms,
               effective("handshake_timeout_ms", Opts, Flags, Env, File, "5000"),
               5000, "a positive integer"},
              {send_timeout_ms,
               effective("send_timeout_ms", Opts, Flags, Env, File, "30000"),
               30000, "a positive integer"},
              {max_pending,
               effective("max_pending", Opts, Flags, Env, File, "64"),
               64, "a positive integer"}],
    case parse_positive_values(Values, #{}) of
        {ok, Parsed} ->
            case parse_suite(effective("suite", Opts, Flags, Env, File,
                                       "aesgcm_sha512")) of
                {ok, Suite} ->
                    case parse_suites(effective("accept_suites", Opts, Flags,
                                                Env, File, "aesgcm_sha512")) of
                        {ok, AcceptSuites} ->
                            KeyOptions = key_option_settings(Opts, Flags, Env, File),
                            HsOpts = Parsed#{suite => Suite,
                                             accept_suites => AcceptSuites},
                            {ok, #{suite => Suite,
                                   accept_suites => AcceptSuites,
                                   hs_opts => HsOpts,
                                   key_options => KeyOptions,
                                   max_pending => maps:get(max_pending, Parsed),
                                   send_timeout_ms =>
                                       maps:get(send_timeout_ms, Parsed)}};
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

argument_settings() ->
    case init:get_argument(noisegate) of
        {ok, Groups} ->
            lists:foldl(fun add_argument_group/2, #{}, Groups);
        error ->
            #{}
    end.

add_argument_group(Group, Acc) ->
    add_argument_pairs(Group, Acc).

add_argument_pairs([Key, Value | Rest], Acc) ->
    Acc1 = case maps:is_key(Key, Acc) of
               true -> Acc;
               false -> maps:put(Key, Value, Acc)
           end,
    add_argument_pairs(Rest, Acc1);
add_argument_pairs(_, Acc) ->
    Acc.

environment_settings() ->
    Keys = ["dir", "key_file", "generate", "authorized_dirs", "authorized_keys",
            "optfile", "chunk_size", "padding",
            "compression", "rekey_after", "max_packet", "accept_compression",
            "max_bytes_without_rekey", "handshake_timeout_ms", "suite",
            "accept_suites", "max_pending", "send_timeout_ms"],
    lists:foldl(fun(Key, Acc) ->
                        case os:getenv("NOISEGATE_" ++ string:uppercase(Key)) of
                            false -> Acc;
                            "" -> Acc;
                            Value -> maps:put(Key, Value, Acc)
                        end
                end, #{}, Keys).

key_option_settings(Opts, Flags, Env, File) ->
    lists:foldl(fun({StringKey, AtomKey}, Acc) ->
                        case effective(StringKey, Opts, Flags, Env, File, undefined) of
                            undefined -> Acc;
                            Value -> maps:put(AtomKey, Value, Acc)
                        end
                end, #{}, [{"dir", dir}, {"key_file", key_file},
                           {"generate", generate},
                           {"authorized_dirs", authorized_dirs},
                           {"authorized_keys", authorized_keys}]).

effective(Key, Opts, Flags, Env, Default) ->
    case maps:find(option_atom(Key), Opts) of
        {ok, Value} -> Value;
        error ->
            case maps:find(Key, Opts) of
                {ok, Value} -> Value;
                error ->
                    case maps:find(Key, Flags) of
                        {ok, Value} -> Value;
                        error ->
                            case maps:find(Key, Env) of
                                {ok, Value} -> Value;
                                error -> Default
                            end
                    end
            end
    end.

effective(Key, Opts, Flags, Env, File, Default) ->
    case effective(Key, Opts, Flags, Env, undefined) of
        undefined ->
            case maps:find(Key, File) of
                {ok, Value} -> Value;
                error -> Default
            end;
        Value ->
            Value
    end.

option_atom("dir") -> dir;
option_atom("generate") -> generate;
option_atom("authorized_dirs") -> authorized_dirs;
option_atom("authorized_keys") -> authorized_keys;
option_atom("key_file") -> key_file;
option_atom("optfile") -> optfile;
option_atom("chunk_size") -> chunk_size;
option_atom("padding") -> padding;
option_atom("compression") -> compression;
option_atom("rekey_after") -> rekey_after;
option_atom("max_packet") -> max_packet;
option_atom("accept_compression") -> accept_compression;
option_atom("max_bytes_without_rekey") -> max_bytes_without_rekey;
option_atom("handshake_timeout_ms") -> handshake_timeout_ms;
option_atom("suite") -> suite;
option_atom("accept_suites") -> accept_suites;
option_atom("max_pending") -> max_pending;
option_atom("send_timeout_ms") -> send_timeout_ms.

policy_layer(Settings) ->
    lists:foldl(fun({StringKey, AtomKey}, Acc) ->
                        case setting_find(StringKey, AtomKey, Settings) of
                            {ok, Value} -> maps:put(AtomKey, Value, Acc);
                            error -> Acc
                        end
                end, #{},
                [{"chunk_size", chunk_size},
                 {"padding", padding},
                 {"compression", compression},
                 {"rekey_after", rekey_after},
                 {"max_packet", max_packet},
                 {"accept_compression", accept_compression},
                 {"max_bytes_without_rekey", max_bytes_without_rekey}]).

setting_find(StringKey, AtomKey, Settings) ->
    case maps:find(AtomKey, Settings) of
        {ok, _} = Found -> Found;
        error -> maps:find(StringKey, Settings)
    end.

parse_positive_values([], Acc) ->
    {ok, Acc};
parse_positive_values([{Key, Value, Default, Allowed} | Rest], Acc) ->
    case positive_integer(Value) of
        {ok, Integer} ->
            parse_positive_values(Rest, maps:put(Key, Integer, Acc));
        error ->
            case Value of
                undefined ->
                    parse_positive_values(Rest, maps:put(Key, Default, Acc));
                _ ->
                    {error, {invalid_setting, Key, Value, Allowed}}
            end
    end.

positive_integer(Value) when is_integer(Value), Value > 0 ->
    {ok, Value};
positive_integer(Value) when is_list(Value); is_binary(Value) ->
    try string:to_integer(to_list(Value)) of
        {Integer, ""} when Integer > 0 -> {ok, Integer};
        _ -> error
    catch
        _:_ -> error
    end;
positive_integer(_) ->
    error.

parse_suite(Value) ->
    case suite_atom(Value) of
        {ok, _} = Ok -> Ok;
        error ->
            {error, {invalid_setting, suite, Value,
                     "chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b"}}
    end.

parse_suites(Value) when is_list(Value), Value =/= [], is_atom(hd(Value)) ->
    case lists:all(fun(S) -> suite_atom(S) =/= error end, Value) of
        true -> {ok, Value};
        false -> invalid_suites(Value)
    end;
parse_suites(Value) when is_list(Value); is_binary(Value) ->
    Names = [string:trim(Name) || Name <- string:split(to_list(Value), ",", all)],
    case Names =/= [] andalso lists:all(fun(Name) -> Name =/= "" end, Names) of
        true ->
            case [Suite || Name <- Names, {ok, Suite} <- [suite_atom(Name)]] of
                Suites when length(Suites) =:= length(Names) -> {ok, Suites};
                _ -> invalid_suites(Value)
            end;
        false -> invalid_suites(Value)
    end;
parse_suites(Value) ->
    invalid_suites(Value).

suite_atom(chachapoly_blake2b) -> {ok, chachapoly_blake2b};
suite_atom(aesgcm_sha512) -> {ok, aesgcm_sha512};
suite_atom(aesgcm_sha256) -> {ok, aesgcm_sha256};
suite_atom(aesgcm_blake2b) -> {ok, aesgcm_blake2b};
suite_atom("chachapoly_blake2b") -> {ok, chachapoly_blake2b};
suite_atom("aesgcm_sha512") -> {ok, aesgcm_sha512};
suite_atom("aesgcm_sha256") -> {ok, aesgcm_sha256};
suite_atom("aesgcm_blake2b") -> {ok, aesgcm_blake2b};
suite_atom(<<"chachapoly_blake2b">>) -> {ok, chachapoly_blake2b};
suite_atom(<<"aesgcm_sha512">>) -> {ok, aesgcm_sha512};
suite_atom(<<"aesgcm_sha256">>) -> {ok, aesgcm_sha256};
suite_atom(<<"aesgcm_blake2b">>) -> {ok, aesgcm_blake2b};
suite_atom(_) -> error.

invalid_suites(Value) ->
    {error, {invalid_setting, accept_suites, Value,
             "comma-separated suite names from chachapoly_blake2b, aesgcm_sha512, aesgcm_sha256, aesgcm_blake2b"}}.

to_list(Value) when is_binary(Value) ->
    unicode:characters_to_list(Value);
to_list(Value) when is_list(Value) ->
    Value.

%%
%% Config file (-noisegate_optfile)
%%

%% Locates the config file: the `optfile` option, a `-noisegate optfile Path`
%% flag, a `-noisegate_optfile Path` flag, or `NOISEGATE_OPTFILE`, in that
%% order.
optfile_settings(Opts, Flags, Env) ->
    case optfile_path(Opts, Flags, Env) of
        undefined ->
            {ok, #{}};
        Path ->
            read_optfile(Path)
    end.

optfile_path(Opts, Flags, Env) ->
    case effective("optfile", Opts, Flags, Env, undefined) of
        undefined ->
            init_optfile_path(Env);
        Path ->
            Path
    end.

init_optfile_path(Env) ->
    case init:get_argument(noisegate_optfile) of
        {ok, Groups} ->
            case [P || G <- Groups, P <- G] of
                [] -> env_optfile(Env);
                [Path | _] -> Path
            end;
        error ->
            env_optfile(Env)
    end.

env_optfile(Env) ->
    case maps:find("optfile", Env) of
        {ok, Path} -> Path;
        error -> undefined
    end.

%% Reads a config file in the spirit of `-ssl_dist_optfile`: Erlang term
%% syntax, one `{Key, Value}` tuple per setting, for example `{suite,
%% aesgcm_blake2b}.` or `{authorized_keys, [{"a@h", "base64key"}]}.`. Values
%% accept the native terms and the string forms used by flags and env.
-spec read_optfile(file:filename()) -> {ok, map()} | {error, term()}.
read_optfile(Path) ->
    case file:consult(Path) of
        {ok, Terms} ->
            file_settings(Terms, Path, #{});
        {error, Reason} ->
            {error, {bad_optfile, Path, Reason}}
    end.

file_settings([], _Path, Acc) ->
    {ok, Acc};
file_settings([{Key, Value} | Rest], Path, Acc) ->
    case file_key(Key) of
        {ok, StringKey} ->
            case expand_env(Value) of
                {ok, Expanded} ->
                    file_settings(Rest, Path, Acc#{StringKey => Expanded});
                missing ->
                    file_settings(Rest, Path, Acc);
                {error, Why} ->
                    {error, {bad_optfile, Path, Why}}
            end;
        error ->
            {error, {bad_optfile, Path, {invalid_key, Key}}}
    end;
file_settings([Term | _], Path, _Acc) ->
    {error, {bad_optfile, Path, {invalid_term, Term}}}.

file_key(Key) when is_atom(Key) ->
    {ok, atom_to_list(Key)};
file_key(Key) when is_binary(Key) ->
    {ok, binary_to_list(Key)};
file_key(Key) when is_list(Key) ->
    {ok, Key};
file_key(_) ->
    error.

%% Values of the form `{env, "VAR"}` are read from the OS environment. An
%% unset or empty variable removes the setting (the default applies); inside
%% lists, `{env, "VAR"}` items expand in place and missing ones are dropped.
expand_env({env, Var}) ->
    env_value(Var);
expand_env(Value) when is_list(Value), Value =/= [], not is_integer(hd(Value)) ->
    expand_env_items(Value, []);
expand_env(Value) ->
    {ok, Value}.

expand_env_items([], Acc) ->
    {ok, lists:reverse(Acc)};
expand_env_items([Item | Rest], Acc) ->
    case expand_env(Item) of
        {ok, Expanded} ->
            expand_env_items(Rest, [Expanded | Acc]);
        missing ->
            expand_env_items(Rest, Acc);
        {error, _} = Error ->
            Error
    end.

env_value(Var) when is_list(Var), Var =/= [], is_integer(hd(Var)) ->
    case os:getenv(Var) of
        false -> missing;
        "" -> missing;
        Value -> {ok, Value}
    end;
env_value(Var) ->
    {error, {invalid_env, Var}}.
