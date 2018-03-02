#!/bin/bash

n_random_chars () {
	cat /dev/urandom | tr -dc 'a-z0-9' | head -c $1
}

for run in {1..1000}
do
	echo "0a$( n_random_chars 3 )18$( n_random_chars 8 )02$( n_random_chars 8 )28$( n_random_chars 5 )" 

done
