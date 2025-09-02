# Unit tests and linting

Activate your virtual environment and install package requirements:

```
source venv/bin/activate
python3 -m pip install -e .
```

Then run any of these commands:

## Linting

```
ruff check .
```

## Running unit tests locally

```
pytest -v
```

Option to suppress logging:
```
pytest -v -s
```

Options for using `coverage` library:
```bash
coverage run -m pytest -v
coverage run -m pytest -v -s
coverage run -m pytest -v -s --durations=0
coverage run -m pytest -k test_orchestrator -v -s
coverage run -m pytest -k "test_request_cert_success" -s -v
```

Generate a local coverage report:
```bash
coverage report -m
```

Generate a detailed coverage report:
```bash
coverage html
open htmlcov/index.html
```

## Running the pytest workflow

This application comes packaged with a GitHub Actions workflow (see .github/workflows/pytest.yaml) that can be triggered manually from the GitHub Actions UI. For more information, see the GitHub docs for [Manually running a workflow](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

# Testing with curl calls

ALWAYS use the `process?testmode=test` endpoint for testing. This sets a `testmode` value that persists throughout the workflow and prevents loading test certificates to Fastly. `testmode` is always enabled when the application is running in a `local` (default) or `staging` environment, and can be used optionally in a `production` environment.

Set up your local environment per the steps outlined in the README.

Once the Flask app is running, open a new tab and make a `curl` call to the internal endpoint to test processing domains.

You will need a `Flask-Key` value to pass as part of the `curl` call. That value corresponds to the `FLASK_SECRET_KEY`.

```
curl http://your.host/process?testmode=test -H "Flask-Key: FLASK_SECRET_KEY"
```

Note: Your `curl` call will eventually return a `504 Gateway Time-out`. There is a point in the workflow where the app sleeps for up to 60 seconds while DNS changes are upserted. If you are tailing the application log, you'll see that the process is still running.

