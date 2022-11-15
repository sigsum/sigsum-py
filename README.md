# sigsum-witness-py
An implementation of a witness that cosigns a sigsum log.

## Installation

### From git

Install the sigsum witness directly from the git repository using pip:

```
pip install git+https://git.glasklar.is/sigsum/core/sigsum-py.git
```



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

### Setup

We use [poetry](https://python-poetry.org/), to manage dependencies. It might
be available as an OS package in your distribution, otherwise you can use pip
to install it. E.g. to install poetry with pip for the current user:

```
pip install --user poetry
```

Poetry automatically creates and manages a virtual environement for each
project. So once it is installed, you can setup your project environment
by installing the dependencies with:

```
poetry install
```

### Running things locally

You can then run commands in the local virtual environment with `poetry run`.
This can be used to start a local witness:
```
poetry run sigsum-witness
```

Or to run tests with [pytest](https://pytest.org/):
```
$ poetry run pytest
```

### Updating dependencies

Direct runtime and development dependencies are specified in `pyproject.toml`
and poetry will pin the full dependency tree in `poetry.lock`.  To update
dependencies to the latest version compatible with `pyproject.toml`, use
`poetry update <package>` (leave out the package name to update all
dependencies.)

## License

This code is licensed under the 2-Clause BSD License.

The full license text can be found in the file LICENSE.

This license is also known as the BSD-2-Clause and the Simplified BSD
License.
