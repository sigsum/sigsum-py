#! /bin/bash

set -e

# Go to the directory this scripts lives in
cd $(dirname "$(realpath "$0")")

# Maybe start sigsum_submit.py via poetry.
#
# If POETRY_RUN is explicitly set in the environment, use that.
# Otherwise, set to "poetry run" if poetry is available and there is
# no active python venv.

# Set POETRY_RUN="poetry run", unless it , or a python venv is active.
if [[ ! -v POETRY_RUN ]] ; then
    POETRY_RUN=""
    type poetry >/dev/null 2>&1 && [[ -z "$VIRTUAL_ENV" ]] && \
	POETRY_RUN="poetry run"
fi

# Install sigsum tools, in a local directory
GOBIN="$(pwd)"/bin go install sigsum.org/log-go/cmd/...@v0.14.0
GOBIN="$(pwd)"/bin go install sigsum.org/sigsum-go/cmd/...@v0.4.0

./bin/sigsum-key gen -o tmp.log-key
./bin/sigsum-key gen -o tmp.submit-key

./bin/sigsum-key gen -o tmp.witness-key

echo "witness W $(./bin/sigsum-key hex -k tmp.witness-key.pub) http://localhost:5000" > tmp.policy
echo "quorum W" >> tmp.policy

# Start sigsum log server
rm -f tmp.log-sth tmp.log-sth.startup tmp.log-server.log
./bin/sigsum-mktree --sth-file tmp.log-sth
./bin/sigsum-log-primary \
    --key-file tmp.log-key --policy-file tmp.policy \
    --interval=1s --log-level=debug --log-file=tmp.log-server.log --backend=ephemeral --sth-file tmp.log-sth &

SIGSUM_PID=$!
WITNESS_PID=

function cleanup () {
    kill ${SIGSUM_PID} ${WITNESS_PID}
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
	if curl -sS http://localhost:6965/get-tree-head |tee tmp.get-tree-head | grep "^size=$1"'$' >/dev/null ; then
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
	if curl -sS http://localhost:6965/get-tree-head | tee tmp.get-tree-head | grep "^size=$1"'$' >/dev/null ; then
	    grep cosignature= tmp.get-tree-head >/dev/null && return 0
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

# Use <(...) trick to start in background, under ssh-agent.
read WITNESS_PID < <(ssh-agent sh <<EOF
ssh-add tmp.witness-key
echo \$\$
# By default, listens on localhost (IPv4 only), port 5000
exec $POETRY_RUN ../sigsum_witness.py -d $(pwd) --ssh-agent --bootstrap-log -s tmp.witness-key.private -l $(./bin/sigsum-key hex -k tmp.log-key.pub) -v >tmp.witness.log 2>&1
EOF
)

wait_cosigned_tree_head 2

add_leaf 3
add_leaf 4
wait_cosigned_tree_head 4

exit 0
