from datetime import datetime

from tlstool.database import db


class Domain(db.Model):
    __tablename__ = 'domains'
    __table_args__ = (
        db.PrimaryKeyConstraint('id', name='pk_user_id'),
        db.UniqueConstraint('name', name='domains_name_key')
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    tld = db.Column(db.String(50), nullable=False)
    registrar_id = db.Column(db.Integer)
    exp_date = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    zone_id = db.Column(db.String(255), nullable=True)
    nameservers = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(255), nullable=True)
    registered = db.Column(db.Boolean, default=True)
    ok_to_delete = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text, nullable=True)
    registrant_contact_id = db.Column(db.Integer, nullable=True)
    admin_contact_id = db.Column(db.Integer, nullable=True)
    tech_contact_id = db.Column(db.Integer, nullable=True)
    expired = db.Column(db.Boolean, default=False)
    fastly_cert = db.Column(db.Boolean, default=False)
    origin_id = db.Column(db.Integer, nullable=True)
    tls_id = db.Column(db.Integer, nullable=True)
    tls_exp_date = db.Column(db.DateTime(timezone=True), nullable=True, default=datetime.utcnow)
    owned = db.Column(db.Boolean, default=True)
    last_updated = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    last_updated_by = db.Column(db.String(255), nullable=True)
    tls_issuer = db.Column(db.String(16), nullable=True)
    fastly_service = db.Column(db.String(16), nullable=True)


class Tls(db.Model):
    __tablename__ = 'tls'
    __table_args__ = (
        db.PrimaryKeyConstraint('id', name='tls_pkey'),
        {'comment': 'This table stores info from the TLS tool, written at the time the cert is created.'}
    )

    id = db.Column(db.Integer, primary_key=True)
    fastly_id = db.Column(db.String(40), nullable=True)
    not_after = db.Column(db.DateTime, nullable=True)
    not_before = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=True)

class Tlsfastly(db.Model):
    __tablename__ = 'tlsfastly'
    __table_args__ = (
        db.PrimaryKeyConstraint('id', name='tlsfastly_pkey'),
        db.UniqueConstraint('cert_id', name='tlsfastly_cert_id_key'),
        {'comment': 'This table stores more detailed certificate metadata pulled via the Fastly PTLS API.'}
    )

    id = db.Column(db.Integer, primary_key=True)
    cert_id = db.Column(db.String(50), nullable=False)
    not_after = db.Column(db.DateTime, nullable=True)
    not_before = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)
    replace = db.Column(db.Boolean, default=False)
    tls_configuration_id = db.Column(db.String(50), nullable=True)
    tls_configuration_type = db.Column(db.String(50), nullable=True)
    tls_domain_id = db.Column(db.String(200), nullable=True)
    tls_domain_type = db.Column(db.String(50), nullable=True)
    type = db.Column(db.String(50), nullable=True)
