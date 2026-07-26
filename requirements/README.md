# Reproducible Builds

NTH DAO core has no third-party runtime dependency. Optional extras are
locked here so contributors can reproduce the same dependency graph.

## Files

```text
requirements/
|-- README.md
|-- base.txt
|-- crypto.lock.txt
|-- p2p.lock.txt
|-- ux.lock.txt
|-- web.lock.txt
`-- dev.lock.txt
```

`base.txt` is intentionally empty because the core protocol layer is
stdlib-only. Each `*.lock.txt` file pins one optional dependency set.

## Use From A Fresh Checkout

```bash
# Production web console + crypto support
pip install -r requirements/web.lock.txt
pip install -r requirements/crypto.lock.txt
pip install -r requirements/p2p.lock.txt
pip install -e . --no-deps

# Development
pip install -r requirements/dev.lock.txt
pip install -e ".[crypto,p2p,web,ux,dev]"
```

## Regeneration

Regenerate locks deliberately, not opportunistically:

```bash
pip install pip-tools
pip-compile pyproject.toml --extra=crypto -o requirements/crypto.lock.txt
pip-compile pyproject.toml --extra=p2p --generate-hashes --strip-extras \
  --no-emit-index-url --no-emit-trusted-host \
  -o requirements/p2p.lock.txt
pip-compile pyproject.toml --extra=ux -o requirements/ux.lock.txt
pip-compile pyproject.toml --extra=web -o requirements/web.lock.txt
pip-compile pyproject.toml --extra=dev -o requirements/dev.lock.txt
```

Any PR that edits lock files should explain why the dependency graph changed.
