# app/database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

# Create an async engine instance
# connect_args={"check_same_thread": False} is for SQLite, not needed for PostgreSQL.
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG, # Log SQL queries if DEBUG is True
    future=True, # Use 2.0 style features
)

# Create a configured "AsyncSession" class
AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False, # Important for async usage
    autoflush=False,
    autocommit=False
)

# Base class for declarative SQLAlchemy models
Base = declarative_base()

# Dependency to get a DB session
async def get_db_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit() # Commit changes if no exceptions
        except Exception:
            await session.rollback() # Rollback on error
            raise
        finally:
            await session.close()

# Function to create all tables (call this once on app startup if needed)
async def create_db_and_tables():
    async with async_engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all) # Optional: drop tables first for dev
        await conn.run_sync(Base.metadata.create_all)