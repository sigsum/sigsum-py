#! /bin/bash

set -e

# Use a local directory for go deps
export GOPATH="$(pwd)/.go-deps"
mkdir -p "$GOPATH"

# Install sigsum tools.
go install sigsum.org/log-go/cmd/sigsum-log-primary@memory-db
go install sigsum.org/sigsum-go/cmd/sigsum-debug@latest

ln -sf "$GOPATH/bin/sigsum-debug" .
ln -sf "$GOPATH/bin/sigsum-log-primary" .

./sigsum-debug key private > log-key.private
cat log-key.private | ./sigsum-debug key public > log-key.public

./sigsum-debug key private > submit-key.private
cat submit-key.private | ./sigsum-debug key public > submit-key.public

./sigsum-debug key private > witness-key.private
cat witness-key.private | ./sigsum-debug key public > witness-key.public

ls -l witness-key.private
# Start sigsum log server
rm -f log-sth
./sigsum-log-primary \
    --key log-key.private --witnesses $(cat witness-key.public) \
    --interval=3s --log-level=debug --ephemeral-test-backend --sth-path log-sth /dev/null &

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
	echo "signature=$(echo $1 | ./sigsum-debug leaf sign -k $(cat submit-key.private))" 
	echo "public_key=$(cat submit-key.public)"
    } | curl -sS --data-binary @- http://localhost:6965/add-leaf >&2
}

# Wait for a tree head of size 
function wait_tree_head() {
    local i
    for i in $(seq 20) ; do
	if curl -sS http://localhost:6965/get-tree-head-to-cosign |tee response | grep "^tree_size=$1"'$' >/dev/null ; then
	    return 0
	fi
	sleep 1
    done
    return 1
}

function wait_cosigned_tree_head() {
    local i
    for i in $(seq 20) ; do
	if curl -sS http://localhost:6965/get-tree-head-cosigned |tee response | grep "^tree_size=$1"'$' >/dev/null ; then
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

chmod go-rx witness-key.private
yes | ../sigsum-witness.py -u http://localhost:6965/ -d $(pwd) --bootstrap-log -s witness-key.private -l $(cat log-key.public) -i 5 -v
wait_cosigned_tree_head 2

add_leaf 3
add_leaf 4
wait_tree_head 4

../sigsum-witness.py -u http://localhost:6965/ -d $(pwd) --once -s witness-key.private -l $(cat log-key.public) -v
wait_cosigned_tree_head 4

echo >&2 All good

exit 0
