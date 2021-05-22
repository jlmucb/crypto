#!/bin/sh
./test_jitter_collection.exe --print_all=true --test_set=0  --graph_file_name=jitter0.bin --num_samples=1000 --num_loops=5
./test_jitter_collection.exe --print_all=true --test_set=1  --graph_file_name=jitter1.bin --num_samples=1000 --num_loops=5
./test_jitter_collection.exe --print_all=true --test_set=2  --graph_file_name=jitter2.bin --num_samples=1000 --num_loops=5
./test_jitter_collection.exe --print_all=true --test_set=3  --graph_file_name=jitter3.bin --num_samples=1000 --num_loops=5
./test_jitter_collection.exe --print_all=true --test_set=4  --graph_file_name=jitter4.bin --num_samples=1000 --num_loops=5
# python ~/src/github.com/jlmucb/crypto/v2/rng/general_graph.py jitter0.bin jitter0.jpg
# python ~/src/github.com/jlmucb/crypto/v2/rng/general_graph.py jitter1.bin jitter1.jpg
# python ~/src/github.com/jlmucb/crypto/v2/rng/general_graph.py jitter2.bin jitter2.jpg
# python ~/src/github.com/jlmucb/crypto/v2/rng/general_graph.py jitter3.bin jitter3.jpg
# python ~/src/github.com/jlmucb/crypto/v2/rng/general_graph.py jitter4.bin jitter4.jpg

# ./test_full_rng.exe -print_all=true
# ./test_prob.exe --print_all=true

