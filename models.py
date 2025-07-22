#!/usr/bin/env python3
"""
Database Models for Cybersecurity Dataset Generator

SQLAlchemy models for storing datasets, vulnerability entries, 
scraping jobs, and user preferences.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Dataset(Base):
    """Model for storing dataset information"""
    __tablename__ = 'datasets'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    sources = Column(JSON)  # List of data sources used
    total_entries = Column(Integer, default=0)
    file_size = Column(Integer, default=0)  # Size in bytes
    quality_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'name': self.name,
            'description': self.description,
            'sources': self.sources,
            'total_entries': self.total_entries,
            'file_size': self.file_size,
            'quality_score': self.quality_score,
            'created_at': self.created_at.isoformat() if self.created_at is not None else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at is not None else None
        }

class VulnerabilityEntry(Base):
    """Model for storing individual vulnerability entries"""
    __tablename__ = 'vulnerability_entries'
    
    id = Column(Integer, primary_key=True)
    dataset_id = Column(Integer, nullable=False)  # Foreign key to datasets
    source = Column(String(50), nullable=False)  # hackerone, bugcrowd, etc.
    instruction = Column(Text, nullable=False)
    input_text = Column(Text, nullable=False)  # 'input' is a reserved word
    output_text = Column(Text, nullable=False)  # 'output' is a reserved word
    vulnerability_type = Column(String(100))
    severity = Column(String(20))
    cvss_score = Column(Float)
    original_url = Column(String(500))
    content_hash = Column(String(64), unique=True)  # For deduplication
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'dataset_id': self.dataset_id,
            'source': self.source,
            'instruction': self.instruction,
            'input': self.input_text,
            'output': self.output_text,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'original_url': self.original_url,
            'content_hash': self.content_hash,
            'created_at': self.created_at.isoformat() if self.created_at is not None else None
        }

class ScrapingJob(Base):
    """Model for tracking scraping job progress"""
    __tablename__ = 'scraping_jobs'
    
    id = Column(Integer, primary_key=True)
    dataset_id = Column(Integer, nullable=True)  # Links to dataset when completed
    sources = Column(JSON)  # List of sources being scraped
    max_entries_per_source = Column(Integer, default=100)
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    progress = Column(Integer, default=0)  # 0-100
    current_source = Column(String(50))
    total_entries = Column(Integer, default=0)
    errors = Column(JSON)  # List of error messages
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'dataset_id': self.dataset_id,
            'sources': self.sources,
            'max_entries_per_source': self.max_entries_per_source,
            'status': self.status,
            'progress': self.progress,
            'current_source': self.current_source,
            'total_entries': self.total_entries,
            'errors': self.errors,
            'started_at': self.started_at.isoformat() if self.started_at is not None else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at is not None else None,
            'created_at': self.created_at.isoformat() if self.created_at is not None else None
        }

class UserPreferences(Base):
    """Model for storing user preferences and settings"""
    __tablename__ = 'user_preferences'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), nullable=False, unique=True)
    value = Column(JSON)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at is not None else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at is not None else None
        }