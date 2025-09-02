import os
import psycopg2
import subprocess
import time

import pytest

os.environ["FLASK_ENV"] = "local"
os.environ['FASTLY_API_TOKEN'] = '1234567890'
os.environ['FASTLY_TLS_CONFIGURATION_ID'] = 'test_id'
os.environ['AWS_ACCESS_KEY'] = 'test'
os.environ['AWS_SECRET_KEY'] = 'test'
os.environ['AWS_REGION_NAME'] = "us-east-1"

os.environ['LE_DIRECTORY_URL'] = 'https://letsencrypt.org/path/to/directory'
os.environ['LE_ACCOUNT_KEY_SECRET_NAME'] = ''
os.environ['AWS_ACCESS_KEY'] = ''
os.environ['AWS_SECRET_KEY'] = ''

os.environ['FLASK_SECRET_KEY'] = ''
os.environ['SLACK_BOT_TOKEN'] = ''
os.environ['SLACK_WEBHOOK_KEY'] = ''

os.environ['DBNAME'] = 'test_db'
os.environ['DBUSER'] = 'test_user'
os.environ['DBPWD'] = 'test_password'
os.environ['DBHOST'] = 'localhost'

DOCKER_COMPOSE_CMD = ['docker', 'compose']
COMPOSE_FILE = 'tests/docker-compose.test.yaml'
DB_RETRIES = 10
DB_WAIT = 2


@pytest.fixture(scope='session', autouse=True)
def docker_postgres():
    project_root = os.path.dirname(os.path.abspath(__file__))
    compose_path = os.path.join(project_root, '..', COMPOSE_FILE)

    # Start the PostgreSQL container
    subprocess.run(DOCKER_COMPOSE_CMD + ['-f', compose_path, 'up', '-d'], check=True)
    
    # Wait for the database to be ready
    # Retry DB connection
    for i in range(DB_RETRIES):
        try:
            conn = psycopg2.connect(
                dbname="test_db",
                user="test_user",
                password="test_password",
                host="localhost",
                port="55432",
            )
            conn.close()
            break
        except psycopg2.OperationalError:
            if i == DB_RETRIES - 1:
                raise # pragma: no cover
            time.sleep(DB_WAIT)

    # Run tests
    yield

    # Tear down the PostgreSQL container
    subprocess.run(DOCKER_COMPOSE_CMD + ['-f', compose_path, 'down'], check=True)
