from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# Create the base class
Base = declarative_base()

# Get database URL from environment, default to SQLite
# The connection string can contain 'postgres://' which needs to be replaced with 'postgresql://'
DB_URL = os.environ.get('DATABASE_URL', 'sqlite:///washbot.db')
if DB_URL.startswith('postgres://'):
    DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

# Create engine with connection pooling options
engine = create_engine(
    DB_URL,
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=300,    # Recycle connections after 5 minutes
    pool_size=10,        # Maximum number of connections
    max_overflow=20,     # Maximum number of connections to overflow
    pool_timeout=30      # Timeout for getting a connection from the pool
)

# Create scoped session for thread safety
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

# Add query property to models
Base.query = db_session.query_property()

def init_db():
    """Initialize the database schema"""
    # Import all modules with models here
    # to ensure they're registered with the Base
    import models
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

def get_db_connection():
    """Get a database session"""
    return db_session
