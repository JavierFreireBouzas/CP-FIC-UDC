-module(break_md5).
-define(PASS_LEN, 6).
-define(UPDATE_BAR_GAP, 1000).
-define(BAR_SIZE, 40).
-define(MAX_PROC, 4).

-export([break_md5/1,
        break_md5/5,
        break_md5/6,
         pass_to_num/1,
         num_to_pass/1,
         num_to_hex_string/1,
         hex_string_to_num/1,
         break_md5s/1,
         start_processes/7,
         sendMessage/2
        ]).

-export([progress_loop/3]).

% Base ^ Exp

pow_aux(_Base, Pow, 0) ->
    Pow;
pow_aux(Base, Pow, Exp) when Exp rem 2 == 0 ->
    pow_aux(Base*Base, Pow, Exp div 2);
pow_aux(Base, Pow, Exp) ->
    pow_aux(Base, Base * Pow, Exp - 1).

pow(Base, Exp) -> pow_aux(Base, 1, Exp).

%% Number to password and back conversion

num_to_pass_aux(_N, 0, Pass) -> Pass;
num_to_pass_aux(N, Digit, Pass) ->
    num_to_pass_aux(N div 26, Digit - 1, [$a + N rem 26 | Pass]).

num_to_pass(N) -> num_to_pass_aux(N, ?PASS_LEN, []).

pass_to_num(Pass) ->
    lists:foldl(fun (C, Num) -> Num * 26 + C - $a end, 0, Pass).

%% Hex string to Number

hex_char_to_int(N) ->
    if (N >= $0) and (N =< $9) -> N - $0;
       (N >= $a) and (N =< $f) -> N - $a + 10;
       (N >= $A) and (N =< $F) -> N - $A + 10;
       true                    -> throw({not_hex, [N]})
    end.

int_to_hex_char(N) ->
    if (N >= 0)  and (N < 10) -> $0 + N;
       (N >= 10) and (N < 16) -> $A + (N - 10);
       true                   -> throw({out_of_range, N})
    end.

hex_string_to_num(Hex_Str) ->
    lists:foldl(fun(Hex, Num) -> Num*16 + hex_char_to_int(Hex) end, 0, Hex_Str).

num_to_hex_string_aux(0, Str) -> Str;
num_to_hex_string_aux(N, Str) ->
    num_to_hex_string_aux(N div 16,
                          [int_to_hex_char(N rem 16) | Str]).

num_to_hex_string(0) -> "0";
num_to_hex_string(N) -> num_to_hex_string_aux(N, []).

%% Progress bar runs in its own process

progress_loop(N, Bound, T1) ->
    receive
        stop -> ok;
        {progress_report, Checked} ->
            N2 = N + Checked,
            Full_N = N2 * ?BAR_SIZE div Bound,
            Full = lists:duplicate(Full_N, $=),
            Empty = lists:duplicate(?BAR_SIZE - Full_N, $-),
            T2 = erlang:monotonic_time(microsecond),
            io:format("\r[~s~s] ~.2f%   passwords/s = ~.2f", [Full, Empty, N2/Bound*100, Checked/(T2-T1) * 1000000]),
            progress_loop(N2, Bound, T2)
    end.

% break_md5/6 is only used in the first iteration

break_md5(Target_Hashes, N, Bound, Progress_Pid, MssgFnd, _)->
    break_md5(Target_Hashes, N, Bound, Progress_Pid, MssgFnd).

% break_md5/5 iterates checking the possible passwords

break_md5([], _, _, _, _) -> ok; %We have broken all the hashes
break_md5(Target_Hashes, N, N, _, _) -> {not_found, Target_Hashes};  % Checked every possible password
break_md5(Target_Hashes, N, Bound, Progress_Pid, MssgFnd) ->
    if N rem ?UPDATE_BAR_GAP == 0 ->
            Progress_Pid ! {progress_report, ?UPDATE_BAR_GAP}; %Updating the progress bar
       true -> ok
    end,
    receive
            {delete, DeleteHash} ->
                Lst = lists:delete(DeleteHash, Target_Hashes)
            after 0 ->
                Lst = Target_Hashes
    end,
    Pass = num_to_pass(N),
    Hash = crypto:hash(md5, Pass),
    Num_Hash = binary:decode_unsigned(Hash),
    case lists:member(Num_Hash, Lst) of
        true ->
            io:format("\e[2K\r~.16B: ~s~n", [Num_Hash, Pass]),
            MssgFnd ! {found, Num_Hash, self()},
            break_md5(lists:delete(Num_Hash, Lst), N+1, Bound, Progress_Pid, MssgFnd);
        false ->
            break_md5(Lst, N+1, Bound, Progress_Pid, MssgFnd)
    end.

%When it is not possible to create more processes, it returns
%the set of identifiers of the processes, which are going to be
%used by sendMessage

start_processes(0, _, _, _, _,States, _)-> States;

%Function for starting MAX_PROC processes

start_processes(N, Num_Hashes, Bound, Div_hashes,Progress_Pid, States, X) ->
    FirstElmt = Div_hashes * X,                 %First Element to check
    LastElmt = if N == ?MAX_PROC - 1 -> Bound;  %Last Element to check
        true -> Div_hashes * (X+1)
    end,
    State = spawn(?MODULE, break_md5, [Num_Hashes, FirstElmt, LastElmt, Progress_Pid, self(), inicio]),
    start_processes(N-1, Num_Hashes, Bound, Div_hashes ,Progress_Pid, States ++[State], X+1).


%When a password is found, a message is sent

sendMessage(_, []) -> ok;
sendMessage(Process_Pid, Num_Hashes) ->
    receive 
        {found, Hash, FdState} -> [Fd ! {delete, Hash} || Fd <- Process_Pid, Fd /= FdState],
            sendMessage(Process_Pid, lists:delete(Hash, Num_Hashes))
        end.


%% Function for breaking multiple hashes

break_md5s(Hashes) ->
    Bound = pow(26, ?PASS_LEN),
    T = erlang:monotonic_time(microsecond),
    Progress_Pid = spawn(?MODULE, progress_loop, [0, Bound, T]),
    Num_Hashes = lists:map(fun hex_string_to_num/1, Hashes),
    Div_hashes = Bound div ?MAX_PROC,
    Process_Pid = start_processes(?MAX_PROC, Num_Hashes, Bound, Div_hashes ,Progress_Pid, [], 0),
    Res = sendMessage(Process_Pid , Num_Hashes),
    Progress_Pid ! stop,
    Res.


%% Function for breaking a single hash

break_md5(Hash) -> break_md5s([Hash]).