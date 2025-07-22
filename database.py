#!/usr/bin/env python3
"""
Database Manager for Cybersecurity Dataset Generator

Handles all database operations including connection management, 
table creation, and data persistence for vulnerability datasets.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import os
import hashlib
from datetime import datetime, timedelta
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError
from models import Base, Dataset, VulnerabilityEntry, ScrapingJob, UserPreferences
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database operations for the cybersecurity dataset generator"""
    
    def __init__(self, database_url=None):
        self.database_url = database_url or os.getenv('DATABASE_URL')
        if not self.database_url:
            raise ValueError("No database URL provided")
        
        self.engine = create_engine(
            self.database_url, 
            echo=False,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=300,
            connect_args={
                "connect_timeout": 30,
                "application_name": "cybersec_dataset_generator"
            }
        )
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
        # Create tables
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise
    
    def create_dataset(self, filename, name, description, sources):
        """Create a new dataset record"""
        session = self.Session()
        try:
            dataset = Dataset(
                filename=filename,
                name=name,
                description=description,
                sources=sources
            )
            session.add(dataset)
            session.commit()
            logger.info(f"Created dataset: {name}")
            return dataset.id
        except IntegrityError:
            session.rollback()
            logger.warning(f"Dataset with filename {filename} already exists")
            return None
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating dataset: {e}")
            raise
        finally:
            session.close()
    
    def update_dataset(self, dataset_id, **kwargs):
        """Update dataset information"""
        session = self.Session()
        try:
            dataset = session.query(Dataset).filter_by(id=dataset_id).first()
            if dataset:
                for key, value in kwargs.items():
                    if hasattr(dataset, key):
                        setattr(dataset, key, value)
                # updated_at will be automatically set by SQLAlchemy due to onupdate parameter
                session.commit()
                logger.info(f"Updated dataset {dataset_id}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating dataset: {e}")
            raise
        finally:
            session.close()
    
    def get_datasets(self, limit=None):
        """Get all datasets, optionally limited"""
        session = self.Session()
        try:
            query = session.query(Dataset).order_by(desc(Dataset.created_at))
            if limit:
                query = query.limit(limit)
            datasets = query.all()
            return [dataset.to_dict() for dataset in datasets]
        except Exception as e:
            logger.error(f"Error getting datasets: {e}")
            return []
        finally:
            session.close()
    
    def get_dataset_by_filename(self, filename):
        """Get dataset by filename"""
        session = self.Session()
        try:
            dataset = session.query(Dataset).filter_by(filename=filename).first()
            return dataset.to_dict() if dataset else None
        except Exception as e:
            logger.error(f"Error getting dataset by filename: {e}")
            return None
        finally:
            session.close()
    
    def add_vulnerability_entries(self, dataset_id, entries):
        """Add vulnerability entries to database"""
        session = self.Session()
        try:
            added_count = 0
            duplicate_count = 0
            
            for entry in entries:
                # Create content hash for deduplication
                content = f"{entry.get('instruction', '')}{entry.get('input', '')}{entry.get('output', '')}"
                content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                
                # Check if entry already exists
                existing = session.query(VulnerabilityEntry).filter_by(content_hash=content_hash).first()
                if existing:
                    duplicate_count += 1
                    continue
                
                vuln_entry = VulnerabilityEntry(
                    dataset_id=dataset_id,
                    source=entry.get('source', 'unknown'),
                    instruction=entry.get('instruction', ''),
                    input_text=entry.get('input', ''),
                    output_text=entry.get('output', ''),
                    vulnerability_type=entry.get('vulnerability_type'),
                    severity=entry.get('severity'),
                    cvss_score=entry.get('cvss_score'),
                    original_url=entry.get('url'),
                    content_hash=content_hash
                )
                session.add(vuln_entry)
                added_count += 1
            
            session.commit()
            logger.info(f"Added {added_count} vulnerability entries, {duplicate_count} duplicates skipped")
            return added_count, duplicate_count
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding vulnerability entries: {e}")
            raise
        finally:
            session.close()
    
    def get_vulnerability_entries(self, dataset_id, limit=None, offset=None):
        """Get vulnerability entries for a dataset"""
        session = self.Session()
        try:
            query = session.query(VulnerabilityEntry).filter_by(dataset_id=dataset_id)
            query = query.order_by(VulnerabilityEntry.created_at)
            
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)
            
            entries = query.all()
            return [entry.to_dict() for entry in entries]
        except Exception as e:
            logger.error(f"Error getting vulnerability entries: {e}")
            return []
        finally:
            session.close()
    
    def create_scraping_job(self, sources, max_entries_per_source):
        """Create a new scraping job"""
        session = self.Session()
        try:
            job = ScrapingJob(
                sources=sources,
                max_entries_per_source=max_entries_per_source,
                status='pending'
            )
            session.add(job)
            session.commit()
            logger.info(f"Created scraping job {job.id}")
            return job.id
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating scraping job: {e}")
            raise
        finally:
            session.close()
    
    def update_scraping_job(self, job_id, **kwargs):
        """Update scraping job status"""
        session = self.Session()
        try:
            job = session.query(ScrapingJob).filter_by(id=job_id).first()
            if job:
                for key, value in kwargs.items():
                    if hasattr(job, key):
                        setattr(job, key, value)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating scraping job: {e}")
            raise
        finally:
            session.close()
    
    def get_scraping_job(self, job_id):
        """Get scraping job by ID"""
        session = self.Session()
        try:
            job = session.query(ScrapingJob).filter_by(id=job_id).first()
            return job.to_dict() if job else None
        except Exception as e:
            logger.error(f"Error getting scraping job: {e}")
            return None
        finally:
            session.close()
    
    def get_recent_scraping_jobs(self, limit=10):
        """Get recent scraping jobs"""
        session = self.Session()
        try:
            jobs = session.query(ScrapingJob).order_by(desc(ScrapingJob.created_at)).limit(limit).all()
            return [job.to_dict() for job in jobs]
        except Exception as e:
            logger.error(f"Error getting recent scraping jobs: {e}")
            return []
        finally:
            session.close()
    
    def set_user_preference(self, key, value, description=None):
        """Set a user preference"""
        session = self.Session()
        try:
            pref = session.query(UserPreferences).filter_by(key=key).first()
            if pref:
                pref.value = value
                # updated_at will be automatically set by SQLAlchemy due to onupdate parameter
                if description:
                    pref.description = description
            else:
                pref = UserPreferences(key=key, value=value, description=description)
                session.add(pref)
            
            session.commit()
            logger.info(f"Set user preference: {key}")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Error setting user preference: {e}")
            raise
        finally:
            session.close()
    
    def get_user_preference(self, key, default=None):
        """Get a user preference"""
        session = self.Session()
        try:
            pref = session.query(UserPreferences).filter_by(key=key).first()
            return pref.value if pref else default
        except Exception as e:
            logger.error(f"Error getting user preference: {e}")
            return default
        finally:
            session.close()
    
    def get_dataset_statistics(self):
        """Get overall dataset statistics"""
        session = self.Session()
        try:
            total_datasets = session.query(Dataset).count()
            total_entries = session.query(VulnerabilityEntry).count()
            
            # Get vulnerability type distribution
            vuln_types = session.query(VulnerabilityEntry.vulnerability_type).distinct().all()
            vuln_type_counts = {}
            for vuln_type in vuln_types:
                if vuln_type[0]:
                    count = session.query(VulnerabilityEntry).filter_by(vulnerability_type=vuln_type[0]).count()
                    vuln_type_counts[vuln_type[0]] = count
            
            # Get source distribution
            sources = session.query(VulnerabilityEntry.source).distinct().all()
            source_counts = {}
            for source in sources:
                if source[0]:
                    count = session.query(VulnerabilityEntry).filter_by(source=source[0]).count()
                    source_counts[source[0]] = count
            
            return {
                'total_datasets': total_datasets,
                'total_entries': total_entries,
                'vulnerability_types': vuln_type_counts,
                'sources': source_counts
            }
        except Exception as e:
            logger.error(f"Error getting dataset statistics: {e}")
            return {}
        finally:
            session.close()
    
    def cleanup_old_data(self, days=30):
        """Clean up old scraping jobs and unused data"""
        session = self.Session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Remove old failed scraping jobs
            old_jobs = session.query(ScrapingJob).filter(
                ScrapingJob.created_at < cutoff_date,
                ScrapingJob.status.in_(['failed', 'completed'])
            ).delete()
            
            session.commit()
            logger.info(f"Cleaned up {old_jobs} old scraping jobs")
            return old_jobs
        except Exception as e:
            session.rollback()
            logger.error(f"Error cleaning up old data: {e}")
            raise
        finally:
            session.close()