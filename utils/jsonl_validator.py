#!/usr/bin/env python3
"""
JSONL Validator for Cybersecurity Dataset Generator

Validates JSONL files and individual entries to ensure data quality
and format compliance for AI model training.

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import json
import logging
from datetime import datetime
from typing import List, Tuple, Dict, Any

logger = logging.getLogger(__name__)

class JSONLValidator:
    """Validates JSONL files and individual entries"""
    
    def __init__(self):
        self.required_fields = ['instruction', 'input', 'output']
        self.max_field_length = 8000
        self.min_field_length = 3
    
    def validate_file(self, file_path: str) -> Tuple[bool, List[str]]:
        """
        Validate a JSONL file
        
        Args:
            file_path: Path to the JSONL file
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        line_number = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line_number += 1
                    line = line.strip()
                    
                    if not line:  # Skip empty lines
                        continue
                    
                    # Validate JSON structure
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors.append(f"Line {line_number}: Invalid JSON - {str(e)}")
                        continue
                    
                    # Validate entry content
                    entry_errors = self.validate_entry(entry)
                    for error in entry_errors:
                        errors.append(f"Line {line_number}: {error}")
            
            is_valid = len(errors) == 0
            
            if is_valid:
                logger.info(f"JSONL file {file_path} is valid ({line_number} entries)")
            else:
                logger.warning(f"JSONL file {file_path} has {len(errors)} validation errors")
            
            return is_valid, errors
            
        except FileNotFoundError:
            return False, [f"File not found: {file_path}"]
        except Exception as e:
            return False, [f"Error reading file: {str(e)}"]
    
    def validate_entry(self, entry: Dict[str, Any]) -> List[str]:
        """
        Validate a single JSONL entry
        
        Args:
            entry: Dictionary representing a JSONL entry
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check if entry is a dictionary
        if not isinstance(entry, dict):
            errors.append("Entry must be a JSON object")
            return errors
        
        # Check required fields
        for field in self.required_fields:
            if field not in entry:
                errors.append(f"Missing required field: {field}")
            elif not isinstance(entry[field], str):
                errors.append(f"Field '{field}' must be a string")
            elif len(entry[field].strip()) < self.min_field_length:
                errors.append(f"Field '{field}' is too short (minimum {self.min_field_length} characters)")
            elif len(entry[field]) > self.max_field_length:
                errors.append(f"Field '{field}' is too long (maximum {self.max_field_length} characters)")
        
        # Check for common issues (more lenient)
        if 'instruction' in entry:
            instruction = entry['instruction'].lower()
            if 'unknown vulnerability' in instruction or instruction.count('unknown') > 2:
                errors.append("Instruction appears to be generic/placeholder")
        
        if 'output' in entry:
            output = entry['output']
            if len(output.split()) < 2:
                errors.append("Output field appears to be too brief")
        
        # Check for potentially sensitive content (more lenient for cybersecurity training data)
        sensitive_keywords = ['real_password', 'actual_api_key', 'live_secret', 'production_token']
        for field in ['input', 'output']:
            if field in entry:
                content = entry[field].lower()
                for keyword in sensitive_keywords:
                    if keyword in content:
                        errors.append(f"Field '{field}' may contain real sensitive information ({keyword})")
        
        return errors
    
    def validate_dataset_quality(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze overall dataset quality
        
        Args:
            file_path: Path to the JSONL file
            
        Returns:
            Dictionary with quality metrics
        """
        metrics = {
            'total_entries': 0,
            'valid_entries': 0,
            'avg_instruction_length': 0,
            'avg_input_length': 0,
            'avg_output_length': 0,
            'unique_instructions': 0,
            'vulnerability_categories': {},
            'quality_score': 0.0
        }
        
        instructions_seen = set()
        instruction_lengths = []
        input_lengths = []
        output_lengths = []
        vuln_categories = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    metrics['total_entries'] += 1
                    
                    try:
                        entry = json.loads(line)
                        
                        # Validate entry
                        entry_errors = self.validate_entry(entry)
                        if len(entry_errors) == 0:
                            metrics['valid_entries'] += 1
                        
                        # Collect metrics
                        if 'instruction' in entry:
                            instruction = entry['instruction']
                            instructions_seen.add(instruction)
                            instruction_lengths.append(len(instruction))
                            
                            # Categorize vulnerability type
                            category = self._categorize_instruction(instruction)
                            vuln_categories[category] = vuln_categories.get(category, 0) + 1
                        
                        if 'input' in entry:
                            input_lengths.append(len(entry['input']))
                        
                        if 'output' in entry:
                            output_lengths.append(len(entry['output']))
                    
                    except json.JSONDecodeError:
                        continue
            
            # Calculate averages
            if instruction_lengths:
                metrics['avg_instruction_length'] = sum(instruction_lengths) / len(instruction_lengths)
            if input_lengths:
                metrics['avg_input_length'] = sum(input_lengths) / len(input_lengths)
            if output_lengths:
                metrics['avg_output_length'] = sum(output_lengths) / len(output_lengths)
            
            metrics['unique_instructions'] = len(instructions_seen)
            metrics['vulnerability_categories'] = vuln_categories
            
            # Calculate quality score (0-100)
            if metrics['total_entries'] > 0:
                validity_score = (metrics['valid_entries'] / metrics['total_entries']) * 40
                diversity_score = min((metrics['unique_instructions'] / metrics['total_entries']) * 30, 30)
                length_score = min((metrics['avg_output_length'] / 100) * 20, 20)
                category_score = min(len(vuln_categories) * 2, 10)
                
                metrics['quality_score'] = validity_score + diversity_score + length_score + category_score
            
        except Exception as e:
            logger.error(f"Error analyzing dataset quality: {e}")
        
        return metrics
    
    def _categorize_instruction(self, instruction: str) -> str:
        """Categorize instruction by vulnerability type"""
        instruction_lower = instruction.lower()
        
        categories = {
            'xss': ['xss', 'cross-site scripting'],
            'sql_injection': ['sql', 'injection'],
            'csrf': ['csrf', 'cross-site request forgery'],
            'ssrf': ['ssrf', 'server-side request forgery'],
            'rce': ['rce', 'remote code execution'],
            'file_inclusion': ['lfi', 'rfi', 'file inclusion'],
            'idor': ['idor', 'insecure direct object'],
            'privilege_escalation': ['privilege escalation', 'escalate'],
            'buffer_overflow': ['buffer overflow', 'overflow'],
            'cve_analysis': ['cve', 'vulnerability analysis']
        }
        
        for category, keywords in categories.items():
            if any(keyword in instruction_lower for keyword in keywords):
                return category
        
        return 'other'
    
    def generate_validation_report(self, file_path: str) -> str:
        """
        Generate a comprehensive validation report
        
        Args:
            file_path: Path to the JSONL file
            
        Returns:
            Formatted validation report as string
        """
        is_valid, errors = self.validate_file(file_path)
        quality_metrics = self.validate_dataset_quality(file_path)
        
        report = f"""
JSONL Dataset Validation Report
===============================

File: {file_path}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

VALIDATION RESULTS:
------------------
Overall Status: {'VALID' if is_valid else 'INVALID'}
Total Errors: {len(errors)}

QUALITY METRICS:
---------------
Total Entries: {quality_metrics['total_entries']}
Valid Entries: {quality_metrics['valid_entries']}
Unique Instructions: {quality_metrics['unique_instructions']}
Quality Score: {quality_metrics['quality_score']:.1f}/100

AVERAGE LENGTHS:
---------------
Instructions: {quality_metrics['avg_instruction_length']:.1f} characters
Input: {quality_metrics['avg_input_length']:.1f} characters
Output: {quality_metrics['avg_output_length']:.1f} characters

VULNERABILITY CATEGORIES:
------------------------
"""
        
        for category, count in quality_metrics['vulnerability_categories'].items():
            percentage = (count / quality_metrics['total_entries']) * 100 if quality_metrics['total_entries'] > 0 else 0
            report += f"{category.replace('_', ' ').title()}: {count} ({percentage:.1f}%)\n"
        
        if errors:
            report += f"\nERRORS FOUND:\n"
            report += "-" * 13 + "\n"
            for error in errors[:20]:  # Limit to first 20 errors
                report += f"• {error}\n"
            
            if len(errors) > 20:
                report += f"... and {len(errors) - 20} more errors\n"
        
        return report
