from __future__ import annotations
from flask import Flask
from tlstool.database import db

def init_db(app: Flask, *, drop_first: bool = False) -> None:
    """Create (and optionally drop) all tables using the Flask app context.
    Ensures models are imported so metadata is populated.
    """
    uri = app.config.get("SQLALCHEMY_DATABASE_URI")
    if not uri:
        raise RuntimeError(
            "SQLALCHEMY_DATABASE_URI is not set. Configure a database URI before initializing."
        )

    with app.app_context():
        # Import models here to ensure they're registered with db.metadata
        # (avoids circular imports at module top-level).
        from . import models  # noqa: F401

        if drop_first:
            db.drop_all()
        db.create_all()
        app.logger.info("Initialized DB at %r", uri)

