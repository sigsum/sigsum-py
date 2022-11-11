# sigsum-witness-py
An implementation of a witness that cosigns a sigsum log.

## License

This code is licensed under the 2-Clause BSD License.

The full license text can be found in the file LICENSE.

This license is also known as the BSD-2-Clause and the Simplified BSD
License.


## Usage

### Use with ssh-agent

The witness supports using an ssh-agent to perform signing operation.  This
allow the private key material to be better protected by e.g. running the agent
with a separate user, or accessing a hardware token. The agent should have
exactly one key of type ed25519.

E.g.:
```
ssh-keygen -t ed25519 -N '' -f my-ed25519-key
eval $(ssh-agent)
ssh-add my-ed25519-key
python sigsum-witness.py --ssh-agent ...
```

## Hacking

### Installing dependencies

Use pip to install development dependencies:

```
pip install -r requirements.dev.txt
```


### Running tests

Use [`pytest`](https://docs.pytest.org/) to run the automated tests:

```
$ pytest .
```

### Updating dependencies

Direct runtime (resp. development) dependencies are specified in
`requirements.in` (resp. `requirements.dev.in`) and we use `pip-compile` to pin
the full dependency tree in `requirements.txt` (resp. `requirements.dev.txt`.)

Note that `requirements.dev.txt` depends on `requirements.txt`, so they need to
be rebuilt in the correct order:

```
pip-compile requirements.in
pip-compile requirements.dev.in
```
