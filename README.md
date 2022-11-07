# sigsum-witness-py
An implementation of a witness that cosigns a sigsum log.

## License

This code is licensed under the 2-Clause BSD License.

The full license text can be found in the file LICENSE.

This license is also known as the BSD-2-Clause and the Simplified BSD
License.

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
