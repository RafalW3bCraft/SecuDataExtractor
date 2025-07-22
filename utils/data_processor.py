#!/usr/bin/env python3
"""
Data Processor for Cybersecurity Dataset Generator

Processes and formats scraped vulnerability data into JSONL format
suitable for AI model training with instruction/input/output structure.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import json
import hashlib
import re
import time
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DataProcessor:
    """Processes and formats scraped vulnerability data into JSONL format"""
    
    def __init__(self):
        self.seen_hashes = set()
    
    def process_entries(self, raw_entries: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
        """
        Process raw entries from a scraper into JSONL format
        
        Args:
            raw_entries: List of raw vulnerability data
            source: Source name (hackerone, bugcrowd, etc.)
            
        Returns:
            List of processed entries in instruction/input/output format
        """
        processed = []
        
        logger.info(f"Processing {len(raw_entries)} entries from {source}")
        
        for raw_entry in raw_entries:
            try:
                # Import the appropriate scraper for parsing
                if source == 'hackerone':
                    from scrapers.hackerone_scraper import HackerOneScraper
                    scraper = HackerOneScraper()
                elif source == 'bugcrowd':
                    from scrapers.bugcrowd_scraper import BugcrowdScraper
                    scraper = BugcrowdScraper()
                elif source == 'exploitdb':
                    from scrapers.exploitdb_scraper import ExploitDBScraper
                    scraper = ExploitDBScraper()
                elif source == 'cve':
                    from scrapers.cve_scraper import CVEScraper
                    scraper = CVEScraper()
                else:
                    logger.warning(f"Unknown source: {source}")
                    continue
                
                # Parse the entry
                processed_entry = scraper.parse_entry(raw_entry)
                
                if processed_entry and self._is_valid_entry(processed_entry):
                    # Clean and normalize the entry
                    cleaned_entry = self._clean_entry(processed_entry)
                    processed.append(cleaned_entry)
                
            except Exception as e:
                logger.error(f"Error processing entry from {source}: {e}")
                continue
        
        logger.info(f"Successfully processed {len(processed)} entries from {source}")
        return processed
    
    def _is_valid_entry(self, entry: Dict[str, Any]) -> bool:
        """Check if an entry has all required fields and valid content"""
        required_fields = ['instruction', 'input', 'output']
        
        # Check for required fields
        for field in required_fields:
            if field not in entry or not entry[field]:
                return False
        
        # Check minimum content length (more lenient)
        if len(entry['instruction']) < 5 or len(entry['output']) < 10:
            return False
        
        # Check for meaningful content (not just "Unknown" values)
        if all(word in entry['instruction'].lower() for word in ['unknown', 'vulnerability']):
            return False
        
        return True
    
    def _clean_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and normalize an entry"""
        cleaned = {}
        
        for key, value in entry.items():
            if isinstance(value, str):
                # Clean whitespace and normalize
                cleaned_value = re.sub(r'\s+', ' ', value.strip())
                # Remove HTML tags if any
                cleaned_value = re.sub(r'<[^>]+>', '', cleaned_value)
                # Limit length
                if len(cleaned_value) > 2000:
                    cleaned_value = cleaned_value[:2000] + "..."
                cleaned[key] = cleaned_value
            else:
                cleaned[key] = value
        
        return cleaned
    
    def remove_duplicates(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate entries based on content hash
        
        Args:
            entries: List of processed entries
            
        Returns:
            List of unique entries
        """
        unique_entries = []
        seen_hashes = set()
        
        logger.info(f"Removing duplicates from {len(entries)} entries")
        
        for entry in entries:
            # Create content hash
            content = f"{entry.get('instruction', '')}{entry.get('input', '')}{entry.get('output', '')}"
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique_entries.append(entry)
        
        removed_count = len(entries) - len(unique_entries)
        logger.info(f"Removed {removed_count} duplicate entries, {len(unique_entries)} unique entries remaining")
        
        return unique_entries
    
    def enhance_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhance entries with additional metadata and formatting
        
        Args:
            entries: List of processed entries
            
        Returns:
            List of enhanced entries
        """
        enhanced = []
        
        for entry in entries:
            enhanced_entry = entry.copy()
            
            # Add metadata
            enhanced_entry['generated_timestamp'] = int(time.time())
            enhanced_entry['format_version'] = '1.0'
            
            # Categorize vulnerability type
            vuln_category = self._categorize_vulnerability(entry.get('instruction', ''))
            if vuln_category:
                enhanced_entry['vulnerability_category'] = vuln_category
            
            # Add difficulty level based on content complexity
            difficulty = self._assess_difficulty(entry)
            enhanced_entry['difficulty_level'] = difficulty
            
            enhanced.append(enhanced_entry)
        
        return enhanced
    
    def _categorize_vulnerability(self, instruction: str) -> str:
        """Categorize vulnerability type from instruction"""
        instruction_lower = instruction.lower()
        
        if any(term in instruction_lower for term in ['xss', 'cross-site scripting']):
            return 'XSS'
        elif any(term in instruction_lower for term in ['sql', 'injection']):
            return 'SQL_INJECTION'
        elif any(term in instruction_lower for term in ['csrf', 'cross-site request forgery']):
            return 'CSRF'
        elif any(term in instruction_lower for term in ['ssrf', 'server-side request forgery']):
            return 'SSRF'
        elif any(term in instruction_lower for term in ['rce', 'remote code execution']):
            return 'RCE'
        elif any(term in instruction_lower for term in ['lfi', 'local file inclusion']):
            return 'LFI'
        elif any(term in instruction_lower for term in ['rfi', 'remote file inclusion']):
            return 'RFI'
        elif any(term in instruction_lower for term in ['idor', 'insecure direct object']):
            return 'IDOR'
        elif any(term in instruction_lower for term in ['privilege escalation']):
            return 'PRIVILEGE_ESCALATION'
        elif any(term in instruction_lower for term in ['buffer overflow']):
            return 'BUFFER_OVERFLOW'
        else:
            return 'OTHER'
    
    def _assess_difficulty(self, entry: Dict[str, Any]) -> str:
        """Assess difficulty level based on entry content"""
        instruction = entry.get('instruction', '').lower()
        output = entry.get('output', '').lower()
        
        # High difficulty indicators
        high_indicators = ['advanced', 'complex', 'chaining', 'bypass', 'sophisticated']
        if any(indicator in instruction or indicator in output for indicator in high_indicators):
            return 'HIGH'
        
        # Medium difficulty indicators
        medium_indicators = ['exploit', 'payload', 'technique', 'authentication']
        if any(indicator in instruction or indicator in output for indicator in medium_indicators):
            return 'MEDIUM'
        
        # Default to beginner
        return 'BEGINNER'
    
    def export_to_jsonl(self, entries: List[Dict[str, Any]], output_path: str) -> bool:
        """
        Export entries to JSONL file
        
        Args:
            entries: List of processed entries
            output_path: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for entry in entries:
                    json_line = json.dumps(entry, ensure_ascii=False, separators=(',', ':'))
                    f.write(json_line + '\n')
            
            logger.info(f"Successfully exported {len(entries)} entries to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSONL: {e}")
            return False
