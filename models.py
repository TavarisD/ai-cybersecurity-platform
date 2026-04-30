from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from datetime import datetime
from database import Base

plan = Column(String, default="free")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    api_key = Column(String, unique=True, index=True, nullable=True)

    usage_count = Column(Integer, default=0)
    last_usage_reset = Column(DateTime, default=datetime.utcnow)

    plan = Column(String, default="free")
    billing_status = Column(String, default="active")

class LogRecord(Base):
    __tablename__ = "log_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    raw_log = Column(Text, nullable=False)
    result = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    value = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)