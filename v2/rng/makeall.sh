#!/bin/sh
make -f entropy_series.mak
make -f test_entropy_collection.mak
make -f test_full_drng.mak
make -f test_full_rng.mak
make -f test_hash_drng.mak
make -f test_jitter_collection.mak
make -f test_prob.mak
make -f test_rng.mak

