#!/usr/bin/env python3
"""
SecuDataExtractor

A sophisticated Python-powered cybersecurity vulnerability data harvesting 
and processing application designed to automatically collect, validate, and 
transform vulnerability reports into high-quality training datasets for AI 
model fine-tuning.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import os
import json
import time
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from threading import Thread
import zipfile
from io import BytesIO

from scrapers.hackerone_scraper import HackerOneScraper
from scrapers.bugcrowd_scraper import BugcrowdScraper
from scrapers.exploitdb_scraper import ExploitDBScraper
from scrapers.cve_scraper import CVEScraper
from utils.data_processor import DataProcessor
from utils.jsonl_validator import JSONLValidator
from database import DatabaseManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cybersec-dataset-generator-key')

# Initialize database manager
try:
    # Use the provided database URL with better connection settings
    db_url = 'postgresql://neondb_owner:npg_XrizH3pG9Yeg@ep-damp-math-a7j3s41k-pooler.ap-southeast-2.aws.neon.tech/neondb?sslmode=prefer&connect_timeout=30&application_name=cybersec_dataset_generator'
    db_manager = DatabaseManager(database_url=db_url)
    logger.info("Database connection established successfully")
except Exception as e:
    logger.error(f"Failed to connect to database: {e}")
    db_manager = None

# Global variables for tracking scraping progress
scraping_status = {
    'running': False,
    'progress': 0,
    'current_source': '',
    'total_entries': 0,
    'errors': [],
    'start_time': None,
    'output_file': None,
    'job_id': None
}

def scrape_vulnerabilities(sources, max_entries_per_source, output_filename):
    """Background task to scrape vulnerabilities from selected sources"""
    global scraping_status
    
    job_id = None  # Initialize outside try block
    try:
        # Create scraping job in database
        if db_manager:
            try:
                job_id = db_manager.create_scraping_job(sources, max_entries_per_source)
                if job_id is not None:
                    db_manager.update_scraping_job(job_id, 
                        status='running', 
                        started_at=datetime.utcnow()
                    )
            except Exception as e:
                logger.warning(f"Failed to create database job: {e}")
                job_id = None
        
        scraping_status.update({
            'running': True,
            'progress': 0,
            'errors': [],
            'start_time': datetime.now(),
            'output_file': output_filename,
            'total_entries': 0,
            'job_id': job_id
        })
        
        # Initialize scrapers
        scrapers = {
            'hackerone': HackerOneScraper(),
            'bugcrowd': BugcrowdScraper(),
            'exploitdb': ExploitDBScraper(),
            'cve': CVEScraper()
        }
        
        data_processor = DataProcessor()
        validator = JSONLValidator()
        
        all_entries = []
        total_sources = len(sources)
        
        for idx, source in enumerate(sources):
            if source not in scrapers:
                logger.warning(f"Unknown source: {source}")
                continue
                
            scraping_status['current_source'] = source.title()
            scraping_status['progress'] = int((idx / total_sources) * 90)  # 90% for scraping
            
            try:
                logger.info(f"Starting to scrape {source}")
                scraper = scrapers[source]
                raw_entries = scraper.scrape(max_entries=max_entries_per_source)
                
                # Process raw entries into JSONL format
                processed_entries = data_processor.process_entries(raw_entries, source)
                all_entries.extend(processed_entries)
                
                logger.info(f"Scraped {len(processed_entries)} entries from {source}")
                
            except Exception as e:
                error_msg = f"Error scraping {source}: {str(e)}"
                logger.error(error_msg)
                scraping_status['errors'].append(error_msg)
        
        # Remove duplicates
        scraping_status['current_source'] = 'Processing & Deduplicating'
        scraping_status['progress'] = 95
        
        unique_entries = data_processor.remove_duplicates(all_entries)
        scraping_status['total_entries'] = len(unique_entries)
        
        # Save to database and generate JSONL file
        dataset_id = None
        if unique_entries:
            output_path = f"datasets/{output_filename}"
            os.makedirs("datasets", exist_ok=True)
            
            # Create dataset record in database
            if db_manager:
                try:
                    dataset_name = f"Cybersec Dataset {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    dataset_description = f"Generated from sources: {', '.join(sources)}"
                    dataset_id = db_manager.create_dataset(
                        filename=output_filename,
                        name=dataset_name,
                        description=dataset_description,
                        sources=sources
                    )
                    
                    if dataset_id is not None:
                        # Store entries in database
                        added_count, duplicate_count = db_manager.add_vulnerability_entries(dataset_id, unique_entries)
                        
                        # Update dataset statistics
                        file_size = sum(len(json.dumps(entry).encode('utf-8')) for entry in unique_entries)
                        db_manager.update_dataset(dataset_id, 
                            total_entries=len(unique_entries),
                            file_size=file_size,
                            quality_score=round((added_count / len(unique_entries)) * 100, 2) if unique_entries else 0
                        )
                        logger.info(f"Stored {added_count} entries in database, {duplicate_count} duplicates")
                except Exception as e:
                    logger.warning(f"Database storage failed: {e}")
            
            # Generate JSONL file
            with open(output_path, 'w', encoding='utf-8') as f:
                for entry in unique_entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            
            # Validate the generated file
            is_valid, validation_errors = validator.validate_file(output_path)
            if not is_valid:
                scraping_status['errors'].extend(validation_errors)
            
            scraping_status['output_file'] = output_path
        
        # Update scraping job status
        if db_manager and job_id is not None:
            try:
                db_manager.update_scraping_job(job_id,
                    status='completed',
                    completed_at=datetime.utcnow(),
                    total_entries=len(unique_entries),
                    dataset_id=dataset_id,
                    progress=100
                )
            except Exception as e:
                logger.warning(f"Failed to update job status: {e}")
        
        scraping_status['progress'] = 100
        scraping_status['current_source'] = 'Complete'
        logger.info(f"Scraping completed. Generated {len(unique_entries)} unique entries.")
        
    except Exception as e:
        error_msg = f"Fatal error during scraping: {str(e)}"
        logger.error(error_msg)
        scraping_status['errors'].append(error_msg)
        
        # Update job status to failed
        if db_manager and job_id is not None:
            try:
                db_manager.update_scraping_job(job_id,
                    status='failed',
                    completed_at=datetime.utcnow(),
                    errors=scraping_status['errors']
                )
            except Exception as e:
                logger.warning(f"Failed to update failed job status: {e}")
    
    finally:
        scraping_status['running'] = False

@app.route('/')
def index():
    """Main page with scraping configuration"""
    return render_template('index.html')

@app.route('/start_scraping', methods=['POST'])
def start_scraping():
    """Start the scraping process"""
    if scraping_status['running']:
        return jsonify({'error': 'Scraping already in progress'}), 400
    
    data = request.get_json()
    sources = data.get('sources', [])
    max_entries_setting = data.get('max_entries_per_source', 'unlimited')
    
    # Convert max_entries to appropriate value
    if max_entries_setting == 'unlimited':
        max_entries = 999999  # Very high number to simulate unlimited
        logger.info("Starting unlimited harvesting mode - will collect as many entries as possible")
    else:
        max_entries = int(max_entries_setting)
        logger.info(f"Starting limited harvesting mode - max {max_entries} entries per source")
    
    if not sources:
        return jsonify({'error': 'No sources selected'}), 400
    
    # Generate output filename based on mode
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if max_entries_setting == 'unlimited':
        output_filename = f"cybersec_dataset_unlimited_{timestamp}.jsonl"
    else:
        output_filename = f"cybersec_dataset_{max_entries}_{timestamp}.jsonl"
    
    # Start scraping in background thread
    thread = Thread(target=scrape_vulnerabilities, args=(sources, max_entries, output_filename))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'message': 'Scraping started', 
        'filename': output_filename,
        'mode': max_entries_setting,
        'max_entries': max_entries if max_entries_setting != 'unlimited' else 'unlimited'
    })

@app.route('/status')
def get_status():
    """Get current scraping status"""
    status = scraping_status.copy()
    if status['start_time']:
        status['elapsed_time'] = str(datetime.now() - status['start_time']).split('.')[0]
    return jsonify(status)

@app.route('/download/<filename>')
def download_file(filename):
    """Download generated JSONL file"""
    file_path = f"datasets/{filename}"
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    return "File not found", 404

@app.route('/preview/<filename>')
def preview_file(filename):
    """Preview first few lines of generated JSONL file"""
    file_path = f"datasets/{filename}"
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    preview_lines = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= 10:  # Preview first 10 lines
                    break
                preview_lines.append(json.loads(line.strip()))
    except Exception as e:
        return jsonify({'error': f'Error reading file: {str(e)}'}), 500
    
    return jsonify({'preview': preview_lines, 'total_lines': scraping_status.get('total_entries', 0)})

@app.route('/datasets')
def datasets_page():
    """View datasets management page"""
    return render_template('datasets.html')

@app.route('/api/datasets')
def list_datasets():
    """API endpoint to list all generated datasets"""
    datasets_from_db = []
    dataset_files = []
    
    # Get datasets from database
    if db_manager:
        try:
            datasets_from_db = db_manager.get_datasets(limit=50)
            for dataset in datasets_from_db:
                dataset['from_database'] = True
        except Exception as e:
            logger.warning(f"Failed to get datasets from database: {e}")
    
    # Get local files as backup
    datasets_dir = "datasets"
    if os.path.exists(datasets_dir):
        for filename in os.listdir(datasets_dir):
            if filename.endswith('.jsonl'):
                file_path = os.path.join(datasets_dir, filename)
                file_stats = os.stat(file_path)
                
                # Check if this file is already in database
                in_db = any(d['filename'] == filename for d in datasets_from_db)
                if not in_db:
                    dataset_files.append({
                        'filename': filename,
                        'name': filename.replace('.jsonl', '').replace('_', ' ').title(),
                        'file_size': file_stats.st_size,
                        'created_at': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                        'total_entries': sum(1 for _ in open(file_path, 'r', encoding='utf-8')),
                        'sources': ['local'],
                        'quality_score': 0.0,
                        'from_database': False
                    })
    
    # Combine and sort datasets
    all_datasets = datasets_from_db + dataset_files
    all_datasets.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({'datasets': all_datasets})

@app.route('/api/datasets/<int:dataset_id>/entries')
def get_dataset_entries(dataset_id):
    """Get vulnerability entries for a specific dataset"""
    if not db_manager:
        return jsonify({'error': 'Database not available'}), 503
    
    limit = request.args.get('limit', 10, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    try:
        entries = db_manager.get_vulnerability_entries(dataset_id, limit=limit, offset=offset)
        return jsonify({'entries': entries, 'limit': limit, 'offset': offset})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """Get overall dataset statistics"""
    if not db_manager:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        stats = db_manager.get_dataset_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jobs')
def get_scraping_jobs():
    """Get recent scraping jobs"""
    if not db_manager:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        jobs = db_manager.get_recent_scraping_jobs(limit=20)
        return jsonify({'jobs': jobs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs("datasets", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
