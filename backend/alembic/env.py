from sqlalchemy import create_engine

from alembic import context
from app import models  # noqa: F401  (registers tables)
from app.config import get_settings
from app.db import Base

url = context.config.get_main_option("sqlalchemy.url") or get_settings().database_url
engine = create_engine(url)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
