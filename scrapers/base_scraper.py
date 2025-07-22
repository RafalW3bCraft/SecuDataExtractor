#!/usr/bin/env python3
"""
Base Scraper for Cybersecurity Dataset Generator

Abstract base class providing common functionality for all 
vulnerability data scrapers including rate limiting and 
robots.txt compliance.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import time
import requests
import logging
from abc import ABC, abstractmethod
from urllib.robotparser import RobotFileParser
import trafilatura

logger = logging.getLogger(__name__)

class BaseScraper(ABC):
    """Base class for all vulnerability scrapers"""
    
    def __init__(self, base_url, rate_limit=1.0):
        """
        Initialize the scraper
        
        Args:
            base_url (str): Base URL of the target website
            rate_limit (float): Minimum seconds between requests
        """
        self.base_url = base_url
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; CybersecDatasetBot/1.0)'
        })
        self.last_request_time = 0
        self.robots_allowed = self._check_robots_txt()
    
    def _check_robots_txt(self):
        """Check if scraping is allowed by robots.txt"""
        try:
            robots_url = f"{self.base_url}/robots.txt"
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            # Check if our user agent can fetch the base URL
            return rp.can_fetch('*', self.base_url)
        except Exception as e:
            logger.warning(f"Could not check robots.txt for {self.base_url}: {e}")
            return True  # Assume allowed if we can't check
    
    def _rate_limit_request(self):
        """Enforce rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, url, **kwargs):
        """Make a rate-limited HTTP request with better error handling"""
        if not self.robots_allowed:
            logger.warning(f"Robots.txt disallows scraping {self.base_url}")
            return None
        
        self._rate_limit_request()
        
        response = None
        try:
            response = self.session.get(url, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed for {url}: {e}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"Request timeout for {url}: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            if response and response.status_code == 404:
                logger.error(f"URL not found (404): {url}")
            elif response and response.status_code == 403:
                logger.error(f"Access forbidden (403): {url}")
            else:
                status_code = response.status_code if response else "unknown"
                logger.error(f"HTTP error {status_code} for {url}: {e}")
            return None
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def _extract_text_content(self, url):
        """Extract main text content from a webpage using trafilatura"""
        try:
            downloaded = trafilatura.fetch_url(url)
            if downloaded:
                text = trafilatura.extract(downloaded)
                return text
            return None
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {e}")
            return None
    
    @abstractmethod
    def scrape(self, max_entries=100):
        """
        Scrape vulnerability data from the source
        
        Args:
            max_entries (int): Maximum number of entries to scrape
            
        Returns:
            list: List of raw vulnerability data dictionaries
        """
        return []
    
    @abstractmethod
    def parse_entry(self, raw_data):
        """
        Parse a single raw entry into structured format
        
        Args:
            raw_data: Raw data from the source
            
        Returns:
            dict or None: Structured vulnerability data
        """
        return None
