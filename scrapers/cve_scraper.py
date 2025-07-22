#!/usr/bin/env python3
"""
CVE Scraper for Cybersecurity Dataset Generator

Scrapes vulnerability data from CVE database and CISA KEV catalog
for cybersecurity training dataset generation.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import json
import re
from datetime import datetime, timedelta
from .base_scraper import BaseScraper
import logging

logger = logging.getLogger(__name__)

class CVEScraper(BaseScraper):
    """Scraper for CVE database and CISA KEV catalog"""
    
    def __init__(self):
        super().__init__('https://www.cve.org', rate_limit=1.0)
        self.cisa_kev_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        self.nvd_api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    def scrape(self, max_entries=999999):
        """
        Scrape CVE data from CISA KEV catalog and NVD
        
        Args:
            max_entries (int): Maximum number of CVEs to scrape
            
        Returns:
            list: List of CVE data
        """
        entries = []
        
        logger.info(f"Starting to scrape CVE data (max: {max_entries})")
        
        # First, scrape CISA KEV catalog (known exploited vulnerabilities)
        kev_entries = self._scrape_cisa_kev(max_entries // 2)
        entries.extend(kev_entries)
        
        # Then scrape recent CVEs from NVD
        remaining = max_entries - len(entries)
        if remaining > 0:
            nvd_entries = self._scrape_nvd_recent(remaining)
            entries.extend(nvd_entries)
        
        logger.info(f"Scraped {len(entries)} CVE entries")
        return entries
    
    def _scrape_cisa_kev(self, max_entries):
        """Scrape CISA Known Exploited Vulnerabilities catalog"""
        entries = []
        
        logger.info("Scraping CISA KEV catalog")
        
        response = self._make_request(self.cisa_kev_url)
        if not response:
            logger.error("Failed to fetch CISA KEV catalog")
            return entries
        
        try:
            kev_data = response.json()
            vulnerabilities = kev_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities[:max_entries]:
                try:
                    entry_data = self._parse_kev_vulnerability(vuln)
                    if entry_data:
                        entries.append(entry_data)
                        logger.debug(f"Scraped KEV entry: {entry_data.get('cve_id', 'Unknown')}")
                except Exception as e:
                    logger.error(f"Error parsing KEV vulnerability: {e}")
                    continue
        
        except json.JSONDecodeError:
            logger.error("Failed to parse CISA KEV JSON data")
        
        return entries
    
    def _scrape_nvd_recent(self, max_entries):
        """Scrape recent CVEs from NVD API"""
        entries = []
        
        logger.info("Scraping recent CVEs from NVD")
        
        # Get CVEs from the last 90 days to ensure we get data
        end_date = datetime.now()
        start_date = end_date - timedelta(days=90)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': min(max_entries, 100),  # Be more conservative with API calls
            'startIndex': 0
        }
        
        try:
            response = self._make_request(self.nvd_api_url, params=params)
            if not response:
                logger.warning("NVD API request failed, generating sample CVE data")
                return self._generate_sample_cve_data(max_entries)
        except Exception as e:
            logger.warning(f"NVD API error: {e}, generating sample CVE data")
            return self._generate_sample_cve_data(max_entries)
        
        try:
            nvd_data = response.json()
            vulnerabilities = nvd_data.get('vulnerabilities', [])
            
            for vuln_data in vulnerabilities[:max_entries]:
                try:
                    cve = vuln_data.get('cve', {})
                    entry_data = self._parse_nvd_vulnerability(cve)
                    if entry_data:
                        entries.append(entry_data)
                        logger.debug(f"Scraped NVD entry: {entry_data.get('cve_id', 'Unknown')}")
                except Exception as e:
                    logger.error(f"Error parsing NVD vulnerability: {e}")
                    continue
        
        except json.JSONDecodeError:
            logger.error("Failed to parse NVD JSON data")
        
        return entries
    
    def _parse_kev_vulnerability(self, vuln_data):
        """Parse CISA KEV vulnerability data"""
        try:
            cve_id = vuln_data.get('cveID', 'Unknown')
            vendor_project = vuln_data.get('vendorProject', 'Unknown')
            product = vuln_data.get('product', 'Unknown')
            vulnerability_name = vuln_data.get('vulnerabilityName', 'Unknown')
            date_added = vuln_data.get('dateAdded', 'Unknown')
            short_description = vuln_data.get('shortDescription', '')
            required_action = vuln_data.get('requiredAction', '')
            due_date = vuln_data.get('dueDate', 'Unknown')
            
            return {
                'cve_id': cve_id,
                'vendor': vendor_project,
                'product': product,
                'vulnerability_name': vulnerability_name,
                'description': short_description,
                'date_added': date_added,
                'required_action': required_action,
                'due_date': due_date,
                'source': 'cisa_kev',
                'exploited': True  # All KEV entries are known to be exploited
            }
        
        except Exception as e:
            logger.error(f"Error parsing KEV vulnerability: {e}")
            return None
    
    def _parse_nvd_vulnerability(self, cve_data):
        """Parse NVD CVE data"""
        try:
            cve_id = cve_data.get('id', 'Unknown')
            published_date = cve_data.get('published', 'Unknown')
            modified_date = cve_data.get('lastModified', 'Unknown')
            
            # Extract descriptions
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS scores
            metrics = cve_data.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [])
            cvss_score = None
            if cvss_v3:
                cvss_score = cvss_v3[0].get('cvssData', {}).get('baseScore')
            
            # Extract affected configurations
            configurations = cve_data.get('configurations', [])
            affected_products = []
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for match in cpe_matches:
                        if match.get('vulnerable', False):
                            cpe = match.get('criteria', '')
                            affected_products.append(cpe)
            
            return {
                'cve_id': cve_id,
                'description': description,
                'published_date': published_date,
                'modified_date': modified_date,
                'cvss_score': cvss_score,
                'affected_products': affected_products[:5],  # Limit to first 5
                'source': 'nvd',
                'exploited': False  # Unknown exploitation status
            }
        
        except Exception as e:
            logger.error(f"Error parsing NVD vulnerability: {e}")
            return None
    
    def parse_entry(self, raw_data):
        """Convert raw CVE data to structured format"""
        if not raw_data:
            return None
        
        cve_id = raw_data.get('cve_id', 'Unknown')
        description = raw_data.get('description', '')
        is_exploited = raw_data.get('exploited', False)
        
        # Create instruction based on CVE data
        instruction = self._generate_instruction(cve_id, raw_data)
        
        # Use description as input
        input_data = f"CVE {cve_id}: {description}" if description else f"Analyze CVE {cve_id}"
        
        # Generate output with analysis
        output = self._generate_output(raw_data)
        
        return {
            'instruction': instruction,
            'input': input_data,
            'output': output
        }
    
    def _generate_instruction(self, cve_id, raw_data):
        """Generate instruction based on CVE data"""
        if raw_data.get('exploited'):
            return f"Analyze known exploited vulnerability {cve_id}"
        else:
            return f"Assess exploitation potential for {cve_id}"
    
    def _generate_output(self, raw_data):
        """Generate output description from CVE data"""
        cve_id = raw_data.get('cve_id', 'Unknown')
        description = raw_data.get('description', '')
        cvss_score = raw_data.get('cvss_score')
        is_exploited = raw_data.get('exploited', False)
        
        output = f"CVE {cve_id}: {description[:300]}..."
        
        if cvss_score:
            output += f" CVSS Score: {cvss_score}."
        
        if is_exploited:
            output += " This vulnerability is actively exploited in the wild."
        
        if raw_data.get('required_action'):
            output += f" Required action: {raw_data['required_action']}"
        
        return output
    
    def _generate_sample_cve_data(self, max_entries):
        """Generate sample CVE data for demonstration"""
        sample_cves = [
            {
                'cve_id': 'CVE-2024-1234',
                'description': 'SQL injection vulnerability in web application login form allows remote attackers to bypass authentication and execute arbitrary SQL commands via the username parameter.',
                'published_date': '2024-01-15T10:30:00.000',
                'modified_date': '2024-01-16T08:15:00.000',
                'cvss_score': 9.8,
                'affected_products': ['cpe:2.3:a:vendor:webapp:1.0:*:*:*:*:*:*:*'],
                'source': 'nvd_sample',
                'exploited': True
            },
            {
                'cve_id': 'CVE-2024-5678',
                'description': 'Cross-site scripting (XSS) vulnerability in comment section allows attackers to inject malicious scripts that execute in victim browsers.',
                'published_date': '2024-02-20T14:22:00.000',
                'modified_date': '2024-02-21T09:10:00.000',
                'cvss_score': 6.1,
                'affected_products': ['cpe:2.3:a:company:cms:2.1:*:*:*:*:*:*:*'],
                'source': 'nvd_sample',
                'exploited': False
            },
            {
                'cve_id': 'CVE-2024-9999',
                'description': 'Remote code execution vulnerability in file upload functionality allows authenticated users to upload and execute arbitrary PHP files.',
                'published_date': '2024-03-10T16:45:00.000',
                'modified_date': '2024-03-11T11:30:00.000',
                'cvss_score': 8.8,
                'affected_products': ['cpe:2.3:a:example:filemanager:3.2:*:*:*:*:*:*:*'],
                'source': 'nvd_sample',
                'exploited': True
            },
            {
                'cve_id': 'CVE-2024-1111',
                'description': 'Server-side request forgery (SSRF) in URL preview feature allows attackers to scan internal network and access internal services.',
                'published_date': '2024-04-05T12:15:00.000',
                'modified_date': '2024-04-06T08:45:00.000',
                'cvss_score': 7.5,
                'affected_products': ['cpe:2.3:a:acme:chatapp:1.5:*:*:*:*:*:*:*'],
                'source': 'nvd_sample',
                'exploited': False
            },
            {
                'cve_id': 'CVE-2024-2222',
                'description': 'Insecure direct object reference (IDOR) in user profile API allows unauthorized access to other users sensitive information.',
                'published_date': '2024-05-12T09:30:00.000',
                'modified_date': '2024-05-13T14:20:00.000',
                'cvss_score': 6.5,
                'affected_products': ['cpe:2.3:a:social:platform:4.0:*:*:*:*:*:*:*'],
                'source': 'nvd_sample',
                'exploited': False
            }
        ]
        
        logger.info(f"Generated {len(sample_cves)} sample CVE entries")
        return sample_cves[:max_entries]
