import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

database_url = os.getenv("DATABASE_URL", "sqlite:///./secuwatch.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if "sqlite" in database_url else {}

engine = create_engine(database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    scans = relationship("ScanRecord", back_populates="owner")

class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True)
    score = Column(Integer)
    details = Column(JSON) 
    scan_date = Column(DateTime, default=datetime.utcnow)
    
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="scans")

def init_db():
    Base.metadata.create_all(bind=engine)