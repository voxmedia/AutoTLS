import click
from flask import Flask, Response

from tlstool import settings
from tlstool.config import configure_logging
from tlstool.db_init import init_db

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    if test_config:
        app.config.update(test_config)
    else:
        app.config['SECRET_KEY'] = settings.FLASK_SECRET_KEY # pragma: no cover
        app.config['SQLALCHEMY_DATABASE_URI'] = settings.SQLALCHEMY_DATABASE_URI # pragma: no cover
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = settings.SQLALCHEMY_TRACK_MODIFICATIONS # pragma: no cover

    configure_logging()

    @app.route("/healthcheck")
    def healthcheck():
        return Response("<p>Hello World</p>"), 200

    from tlstool.database import db
    db.init_app(app)

    @app.cli.command("init-db")
    @click.option("--drop-first", is_flag=True, help="Drop all tables before creating them.")
    def init_db_command(drop_first: bool) -> None:
        """Initialize the database schema from the current models."""
        init_db(app, drop_first=drop_first)

    from tlstool import orchestrator
    app.register_blueprint(orchestrator.bp)
    app.add_url_rule('/single/<string:domain>', endpoint='process_single_domain')
    app.add_url_rule('/process', endpoint='process_domains')

    from tlstool import domains
    app.register_blueprint(domains.bp)

    from tlstool import storage
    app.register_blueprint(storage.bp)

    from tlstool import certificates
    app.register_blueprint(certificates.bp)

    return app
