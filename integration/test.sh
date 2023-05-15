#! /bin/bash

set -e

# Go to the directory this scripts lives in
cd $(dirname "$(realpath "$0")")

# Install sigsum tools, in a local directory
GOBIN="$(pwd)"/bin go install sigsum.org/log-go/cmd/...@v0.8.0
# log-go@v0.8.0 depends on 0.1.18, but we need newer tools. But it seems 0.1.24 is too new
GOBIN="$(pwd)"/bin go install sigsum.org/sigsum-go/cmd/...@v0.1.21

./bin/sigsum-key gen -o tmp.log-key
./bin/sigsum-key gen -o tmp.submit-key

(umask 077 && ./bin/sigsum-debug key private > tmp.witness-key.private)
cat tmp.witness-key.private | ./bin/sigsum-debug key public > tmp.witness-key.public # hex format
cat tmp.witness-key.public | ./bin/sigsum-key hex-to-pub $(cat tmp.witness-key.public) > tmp.witness-key.pub # ssh format

# Start sigsum log server
rm -f tmp.log-sth
./bin/sigsum-mktree --key tmp.log-key --sth-path tmp.log-sth
./bin/sigsum-log-primary \
    --key tmp.log-key --witnesses tmp.witness-key.pub \
    --interval=3s --log-level=debug --ephemeral-test-backend --sth-path tmp.log-sth /dev/null &

SIGSUM_PID=$!

function cleanup () {
    kill ${SIGSUM_PID}
}

trap cleanup EXIT

function b16encode {
	python3 -c 'import sys; sys.stdout.write(sys.stdin.buffer.read().hex())'
}

function b16decode {
	python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))'
}

function add_leaf () {
    {
	echo "message=$(openssl dgst -binary <(echo $1) | b16encode)"
	echo "signature=$(echo $1 | ./bin/sigsum-debug leaf sign -k tmp.submit-key)"
	echo "public_key=$(./bin/sigsum-key hex -k tmp.submit-key.pub)"
    } | curl -sS --data-binary @- http://localhost:6965/add-leaf >&2
}

# wait_tree_head N waits for a tree head of size N
function wait_tree_head() {
    local i
    for i in $(seq 20) ; do
	if curl -sS http://localhost:6965/get-next-tree-head |tee tmp.next-tree-head | grep "^size=$1"'$' >/dev/null ; then
	    return 0
	fi
	sleep 1
    done
    return 1
}

# wait_cosigned_tree_head N waits for a tree head of size N
function wait_cosigned_tree_head() {
    local i
    for i in $(seq 20) ; do
	if curl -sS http://localhost:6965/get-tree-head | tee tmp.tree-head | grep "^size=$1"'$' >/dev/null ; then
	    return 0
	fi
	sleep 1
    done
    return 1
}

wait_tree_head 0

add_leaf 1
add_leaf 2

wait_tree_head 2

# Always start witnessing with no previous state
rm -f signed-tree-head

yes | ../sigsum_witness.py -u http://localhost:6965/ -d $(pwd) --bootstrap-log -s tmp.witness-key.private -l $(./bin/sigsum-key hex -k tmp.log-key.pub) -i 5 -v
wait_cosigned_tree_head 2

add_leaf 3
add_leaf 4
wait_tree_head 4

../sigsum_witness.py -u http://localhost:6965/ -d $(pwd) --once -s tmp.witness-key.private -l $(./bin/sigsum-key hex -k tmp.log-key.pub) -v
wait_cosigned_tree_head 4

exit 0
