-module(noisegate_settings_tests).

-include_lib("eunit/include/eunit.hrl").

defaults_test() ->
    {ok, Settings} = noisegate_settings:parse(#{}, #{}, #{}),
    ?assertEqual(aesgcm_sha512, maps:get(suite, Settings)),
    ?assertEqual([aesgcm_sha512], maps:get(accept_suites, Settings)),
    ?assertEqual(5000, maps:get(handshake_timeout_ms,
                                maps:get(hs_opts, Settings))),
    ?assertEqual(30000, maps:get(send_timeout_ms, Settings)),
    ?assertEqual(64, maps:get(max_pending, Settings)).

precedence_test() ->
    Opts = #{suite => aesgcm_sha256, chunk_size => 8192, dir => "/opts"},
    Flags = #{"suite" => "aesgcm_blake2b",
              "chunk_size" => "4096",
              "dir" => "/flags"},
    Env = #{"suite" => "chachapoly_blake2b",
            "chunk_size" => "2048",
            "dir" => "/env"},
    {ok, Settings} = noisegate_settings:parse(Opts, Flags, Env),
    ?assertEqual(aesgcm_sha256, maps:get(suite, Settings)),
    ?assertEqual(8192,
                 maps:get(chunk_size, maps:get(sender_policy, Settings))),
    ?assertEqual("/opts", maps:get(dir, maps:get(key_options, Settings))).

flag_over_environment_test() ->
    {ok, Settings} =
        noisegate_settings:parse(#{}, #{"suite" => "aesgcm_sha256"},
                               #{"suite" => "aesgcm_blake2b"}),
    ?assertEqual(aesgcm_sha256, maps:get(suite, Settings)).

invalid_suite_names_allowed_values_test() ->
    ?assertMatch({error, {invalid_setting, suite, "foo",
                          "chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b"}},
                 noisegate_settings:parse(#{suite => "foo"}, #{}, #{})).

invalid_positive_setting_names_allowed_values_test() ->
    ?assertEqual({error, {invalid_setting, max_pending, "zero",
                          "a positive integer"}},
                 noisegate_settings:parse(#{}, #{"max_pending" => "zero"}, #{})).

optfile_layer_test_() ->
    [{"file layer provides settings above the defaults",
      fun() ->
          File = #{"suite" => "aesgcm_blake2b", "chunk_size" => 16384,
                   "dir" => "/optfile", "authorized_keys" => Keys = [{"a@h", "QUJD"}]},
          {ok, Settings} = noisegate_settings:parse(#{}, #{}, #{}, File),
          ?assertEqual(aesgcm_blake2b, maps:get(suite, Settings)),
          ?assertEqual(16384,
                       maps:get(chunk_size, maps:get(sender_policy, Settings))),
          ?assertEqual("/optfile", maps:get(dir, maps:get(key_options, Settings))),
          ?assertEqual(Keys, maps:get(authorized_keys, maps:get(key_options, Settings)))
      end},
     {"explicit options, flags and env override the file",
      fun() ->
          File = #{"suite" => "aesgcm_blake2b", "chunk_size" => 16384},
          {ok, S1} = noisegate_settings:parse(#{suite => aesgcm_sha256}, #{}, #{}, File),
          ?assertEqual(aesgcm_sha256, maps:get(suite, S1)),
          {ok, S2} = noisegate_settings:parse(#{}, #{"chunk_size" => "4096"}, #{}, File),
          ?assertEqual(4096, maps:get(chunk_size, maps:get(sender_policy, S2))),
          {ok, S3} = noisegate_settings:parse(#{}, #{}, #{"suite" => "chachapoly_blake2b"}, File),
          ?assertEqual(chachapoly_blake2b, maps:get(suite, S3))
      end},
     {"file values are validated like the other layers",
      fun() ->
          ?assertEqual({error, {invalid_setting, suite, "foo",
                                "chachapoly_blake2b | aesgcm_sha512 | aesgcm_sha256 | aesgcm_blake2b"}},
                       noisegate_settings:parse(#{}, #{}, #{}, #{"suite" => "foo"}))
      end}].

read_optfile_test_() ->
    [{"reads {Key, Value} tuples, atom or string keys, native or string values",
      fun() -> with_file(cfg(), fun(Path) ->
          {ok, Settings} = noisegate_settings:read_optfile(Path),
          ?assertEqual(aesgcm_blake2b, maps:get("suite", Settings)),
          ?assertEqual(16384, maps:get("chunk_size", Settings)),
          ?assertEqual("/var/lib/noisegate", maps:get("dir", Settings)),
          ?assertEqual(none, maps:get("compression", Settings)),
          ?assertEqual([{"a@host", "QUJD"}, {"b@host", "REVG"}],
                       maps:get("authorized_keys", Settings)),
          ?assertEqual({fixed, 4096}, maps:get("padding", Settings))
      end) end},
     {"% comments are ignored",
      fun() -> with_file("%% noisegate config\n{suite, aesgcm_sha256}. % trailing\n", fun(Path) ->
          ?assertEqual({ok, #{"suite" => aesgcm_sha256}},
                       noisegate_settings:read_optfile(Path))
      end) end},
     {"missing file",
      fun() ->
          ?assertMatch({error, {bad_optfile, _, _}},
                       noisegate_settings:read_optfile("/noisegate/no/such/file.cfg"))
      end},
     {"non-tuple terms are rejected",
      fun() -> with_file("{suite, aesgcm_sha256}.\n[1, 2].\n", fun(Path) ->
          ?assertMatch({error, {bad_optfile, _, {invalid_term, [1, 2]}}},
                       noisegate_settings:read_optfile(Path))
      end) end},
     {"invalid keys are rejected",
      fun() -> with_file("{suite, aesgcm_sha256}.\n{123, x}.\n", fun(Path) ->
          ?assertMatch({error, {bad_optfile, _, {invalid_key, 123}}},
                       noisegate_settings:read_optfile(Path))
      end) end}].

parse_with_optfile_option_test() ->
    {ok, Settings} = parse_with_file(cfg(), fun(Path) ->
        noisegate_settings:parse(#{optfile => Path})
    end),
    ?assertEqual(aesgcm_blake2b, maps:get(suite, Settings)),
    ?assertEqual([{"a@host", "QUJD"}, {"b@host", "REVG"}],
                 maps:get(authorized_keys, maps:get(key_options, Settings))).

bad_optfile_fails_parse_test() ->
    ?assertMatch({error, {bad_optfile, _, _}},
                 noisegate_settings:parse(#{optfile => "/noisegate/no/such/file.cfg"})).

cfg() ->
    "% Noisegate distribution settings\n"
    "{dir, \"/var/lib/noisegate\"}.\n"
    "{suite, aesgcm_blake2b}.\n"
    "{chunk_size, 16384}.\n"
    "{compression, none}.\n"
    "{padding, {fixed, 4096}}.\n"
    "{authorized_keys, [{\"a@host\", \"QUJD\"},\n"
    "                    {\"b@host\", \"REVG\"}]}.\n".

with_file(Content, Fun) ->
    Path = "/tmp/noisegate_cfg_test_"
        ++ integer_to_list(erlang:unique_integer([positive])) ++ ".cfg",
    ok = file:write_file(Path, Content),
    try
        Fun(Path)
    after
        file:delete(Path)
    end.

parse_with_file(Content, Fun) ->
    with_file(Content, Fun).

optfile_env_test_() ->
    [{"a {env, Var} value is read from the OS environment",
      fun() ->
          true = os:putenv("NOISEGATE_TEST_SUITE", "aesgcm_blake2b"),
          try with_file("{suite, {env, \"NOISEGATE_TEST_SUITE\"}}.\n", fun(Path) ->
              {ok, Settings} = noisegate_settings:read_optfile(Path),
              ?assertEqual("aesgcm_blake2b", maps:get("suite", Settings)),
              {ok, Parsed} = noisegate_settings:parse(#{optfile => Path}),
              ?assertEqual(aesgcm_blake2b, maps:get(suite, Parsed))
          end)
          after os:unsetenv("NOISEGATE_TEST_SUITE") end
      end},
     {"an unset or empty variable removes the setting",
      fun() ->
          true = os:unsetenv("NOISEGATE_TEST_CHUNK_SIZE"),
          try with_file("{chunk_size, {env, \"NOISEGATE_TEST_CHUNK_SIZE\"}}.\n", fun(Path) ->
              ?assertEqual({ok, #{}}, noisegate_settings:read_optfile(Path)),
              {ok, Settings} = noisegate_settings:parse(#{optfile => Path}),
              ?assertEqual(65518,
                           maps:get(chunk_size, maps:get(sender_policy, Settings)))
          end)
          after os:unsetenv("NOISEGATE_TEST_CHUNK_SIZE") end
      end},
     {"{env, Var} items expand inside lists and missing ones are dropped",
      fun() ->
          true = os:putenv("NOISEGATE_TEST_KEYS", "c@host R1VG\n"),
          try with_file("{authorized_keys, [{\"a@host\", \"QUJD\"},\n"
                         "                   {env, \"NOISEGATE_TEST_KEYS\"},\n"
                         "                   {env, \"NOISEGATE_TEST_MISSING\"}]}.\n", fun(Path) ->
              {ok, Settings} = noisegate_settings:read_optfile(Path),
              ?assertEqual([{"a@host", "QUJD"}, "c@host R1VG\n"],
                           maps:get("authorized_keys", Settings))
          end)
          after os:unsetenv("NOISEGATE_TEST_KEYS"),
                os:unsetenv("NOISEGATE_TEST_MISSING") end
      end},
     {"a non-string variable name is rejected",
      fun() -> with_file("{suite, {env, 123}}.\n", fun(Path) ->
          ?assertMatch({error, {bad_optfile, _, {invalid_env, 123}}},
                       noisegate_settings:read_optfile(Path))
      end) end}].
