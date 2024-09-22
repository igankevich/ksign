#!/bin/sh

. ./ci/preamble.sh

test_all() {
    cargo test --workspace --quiet --no-run
    cargo test --workspace --no-fail-fast -- --nocapture
}

test_miri() {
    cargo +nightly miri setup --quiet
    do_test_miri --lib --quiet --no-run
    do_test_miri --lib
}

do_test_miri() {
    env MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test "$@"
}

test_all
test_miri
