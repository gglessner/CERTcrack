#!/usr/bin/env python3
"""
CERTcrack.py - A tool for cracking passwords on various certificate file formats

Author: Garland Glessner <gglessner@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict
from datetime import datetime
import re

# Supported certificate file extensions
CERT_EXTENSIONS = {'.pfx', '.p12', '.jks', '.keystore'}  # Added .keystore as alternative to .jks

def is_encrypted_key(file_path: Path) -> bool:
    """
    Check if a key file contains an encrypted private key
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            return any(marker in content for marker in [
                '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                '-----BEGIN ENCRYPTED RSA PRIVATE KEY-----'
            ])
    except Exception:
        return False

def convert_jks_to_p12(jks_path: Path, password: str) -> Tuple[bool, Optional[Path]]:
    """
    Convert a JKS file to PKCS#12 format using keytool.
    Returns (success, temp_file_path) where temp_file_path is the path to the converted file if successful.
    """
    try:
        # Create a temporary file for the PKCS#12 output
        temp_dir = tempfile.gettempdir()
        temp_p12 = Path(temp_dir) / f"{jks_path.stem}_temp.p12"
        
        # Use keytool to convert JKS to PKCS#12
        result = subprocess.run([
            'keytool',
            '-importkeystore',
            '-srckeystore', str(jks_path),
            '-srcstoretype', 'JKS',
            '-srcstorepass', password,
            '-destkeystore', str(temp_p12),
            '-deststoretype', 'PKCS12',
            '-deststorepass', password
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, temp_p12
        return False, None
        
    except Exception as e:
        print(f"Error converting JKS file {jks_path}: {str(e)}")
        return False, None

def find_cert_files(directory: str) -> List[Path]:
    """
    Recursively find all supported certificate files in the given directory
    """
    root_path = Path(directory)
    cert_files = []
    
    # Find standard certificate files (PFX/P12/JKS)
    for ext in CERT_EXTENSIONS:
        cert_files.extend(root_path.rglob(f"*{ext}"))
    
    # Find encrypted key files
    for key_file in root_path.rglob("*.key"):
        if is_encrypted_key(key_file):
            cert_files.append(key_file)
    
    # Find PEM files that contain encrypted private keys
    for pem_file in root_path.rglob("*.pem"):
        if is_encrypted_key(pem_file):  # Reuse the same function since format is similar
            cert_files.append(pem_file)
    
    return cert_files

def get_cert_info(cert_path: Path, password: str) -> Dict[str, str]:
    """
    Extract certificate information including validity dates.
    Returns a dictionary containing certificate details for the end-entity certificate.
    """
    try:
        # Handle different file types
        if cert_path.suffix.lower() in {'.jks', '.keystore'}:
            # Use keytool for JKS files
            cmd = [
                'keytool',
                '-list',
                '-v',
                '-keystore', str(cert_path),
                '-storepass', password
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {"error": "Failed to extract certificate information"}
            
            # Parse keytool output to find all certificates
            cert_text = result.stdout
            certs_info = []
            
            # Find all certificate entries
            cert_entries = re.finditer(r'Certificate\[(\d+)\]:\n(.*?)(?=Certificate\[\d+\]:|$)', cert_text, re.DOTALL)
            
            for cert_entry in cert_entries:
                cert_block = cert_entry.group(2)
                # Extract validity dates
                valid_from = re.search(r'Valid from: (.+) until:', cert_block)
                valid_until = re.search(r'until: (.+)', cert_block)
                
                if valid_from and valid_until:
                    try:
                        from_date = datetime.strptime(valid_from.group(1).strip(), '%a %b %d %H:%M:%S %Z %Y')
                        until_date = datetime.strptime(valid_until.group(1).strip(), '%a %b %d %H:%M:%S %Z %Y')
                        current_date = datetime.now()
                        
                        is_valid = current_date <= until_date
                        days_remaining = (until_date - current_date).days if is_valid else 0
                        
                        # Get certificate alias and key usage
                        alias_match = re.search(r'Alias name: (.+)', cert_block)
                        alias = alias_match.group(1) if alias_match else f"Certificate {cert_entry.group(1)}"
                        
                        # Check if this is an end-entity certificate
                        # Look for key usage that indicates end-entity cert
                        is_ca = False
                        is_end_entity = False
                        
                        # Check for CA usage
                        if re.search(r'Certificate is a CA', cert_block):
                            is_ca = True
                        
                        # Check for end-entity usage
                        if re.search(r'DigitalSignature|KeyEncipherment|KeyAgreement', cert_block):
                            is_end_entity = True
                        
                        certs_info.append({
                            "alias": alias,
                            "not_before": from_date.strftime('%Y-%m-%d %H:%M:%S'),
                            "not_after": until_date.strftime('%Y-%m-%d %H:%M:%S'),
                            "is_valid": is_valid,
                            "days_remaining": days_remaining,
                            "is_ca": is_ca,
                            "is_end_entity": is_end_entity
                        })
                    except ValueError as e:
                        print(f"Warning: Could not parse dates for {alias}: {str(e)}")
                        continue
            
            if not certs_info:
                return {"error": "No valid certificates found"}
            
            # First try to find an end-entity certificate
            end_entity_certs = [cert for cert in certs_info if cert["is_end_entity"] and not cert["is_ca"]]
            if end_entity_certs:
                # If we found end-entity certs, return the one with the most days remaining
                return max(end_entity_certs, key=lambda x: x["days_remaining"])
            
            # If no end-entity certs found, return the first non-CA cert
            non_ca_certs = [cert for cert in certs_info if not cert["is_ca"]]
            if non_ca_certs:
                return max(non_ca_certs, key=lambda x: x["days_remaining"])
            
            # If all certs are CAs, return the one with the most days remaining
            return max(certs_info, key=lambda x: x["days_remaining"])
            
        elif cert_path.suffix.lower() in {'.pfx', '.p12'}:
            # Use OpenSSL for PKCS#12 files
            # First get all certificates
            cmd = [
                'openssl', 'pkcs12',
                '-in', str(cert_path),
                '-clcerts',  # Get client certificates
                '-nokeys',   # Don't include private keys
                '-passin', f'pass:{password}'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {"error": "Failed to extract certificate information"}
            
            # Split the output into individual certificates
            cert_blocks = re.split(r'-----BEGIN CERTIFICATE-----', result.stdout)
            certs_info = []
            
            for cert_block in cert_blocks[1:]:  # Skip the first empty split
                # Reconstruct the certificate
                cert_pem = "-----BEGIN CERTIFICATE-----" + cert_block
                
                # Get certificate info using x509
                x509_cmd = [
                    'openssl', 'x509',
                    '-noout',
                    '-text',
                    '-in', '-'
                ]
                # Convert cert_pem to bytes if it's a string
                cert_input = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
                x509_result = subprocess.run(x509_cmd, input=cert_input, capture_output=True, text=True)
                
                if x509_result.returncode == 0:
                    cert_text = x509_result.stdout
                    not_before = re.search(r'Not Before: (.+)', cert_text)
                    not_after = re.search(r'Not After : (.+)', cert_text)
                    
                    if not_before and not_after:
                        try:
                            not_before_date = datetime.strptime(not_before.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                            not_after_date = datetime.strptime(not_after.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                            current_date = datetime.now()
                            
                            is_valid = current_date <= not_after_date
                            days_remaining = (not_after_date - current_date).days if is_valid else 0
                            
                            # Try to get subject as identifier
                            subject = re.search(r'Subject: (.+)', cert_text)
                            alias = subject.group(1) if subject else f"Certificate {len(certs_info) + 1}"
                            
                            # Check if this is an end-entity certificate
                            is_ca = False
                            is_end_entity = False
                            
                            # Check for CA usage
                            if re.search(r'CA:TRUE', cert_text):
                                is_ca = True
                            
                            # Check for end-entity usage
                            if re.search(r'Digital Signature|Key Encipherment|Key Agreement', cert_text):
                                is_end_entity = True
                            
                            certs_info.append({
                                "alias": alias,
                                "not_before": not_before_date.strftime('%Y-%m-%d %H:%M:%S'),
                                "not_after": not_after_date.strftime('%Y-%m-%d %H:%M:%S'),
                                "is_valid": is_valid,
                                "days_remaining": days_remaining,
                                "is_ca": is_ca,
                                "is_end_entity": is_end_entity
                            })
                        except ValueError as e:
                            print(f"Warning: Could not parse dates for certificate: {str(e)}")
                            continue
            
            if not certs_info:
                return {"error": "No valid certificates found"}
            
            # First try to find an end-entity certificate
            end_entity_certs = [cert for cert in certs_info if cert["is_end_entity"] and not cert["is_ca"]]
            if end_entity_certs:
                # If we found end-entity certs, return the one with the most days remaining
                return max(end_entity_certs, key=lambda x: x["days_remaining"])
            
            # If no end-entity certs found, return the first non-CA cert
            non_ca_certs = [cert for cert in certs_info if not cert["is_ca"]]
            if non_ca_certs:
                return max(non_ca_certs, key=lambda x: x["days_remaining"])
            
            # If all certs are CAs, return the one with the most days remaining
            return max(certs_info, key=lambda x: x["days_remaining"])
            
        else:
            # For other file types (like .key or .pem), try to find matching certificate
            cert_path_possible = cert_path.with_suffix('.crt')
            if not cert_path_possible.exists():
                cert_path_possible = cert_path.with_suffix('.cer')
            if not cert_path_possible.exists():
                return {"error": "No matching certificate file found"}
            
            # Use OpenSSL x509 for the certificate
            cmd = [
                'openssl', 'x509',
                '-in', str(cert_path_possible),
                '-noout',
                '-text'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {"error": "Failed to extract certificate information"}
            
            cert_text = result.stdout
            not_before = re.search(r'Not Before: (.+)', cert_text)
            not_after = re.search(r'Not After : (.+)', cert_text)
            
            if not_before and not_after:
                not_before_date = datetime.strptime(not_before.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                not_after_date = datetime.strptime(not_after.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
                current_date = datetime.now()
                
                is_valid = current_date <= not_after_date
                days_remaining = (not_after_date - current_date).days if is_valid else 0
                
                # Check if this is an end-entity certificate
                is_ca = bool(re.search(r'CA:TRUE', cert_text))
                is_end_entity = bool(re.search(r'Digital Signature|Key Encipherment|Key Agreement', cert_text))
                
                return {
                    "alias": cert_path_possible.name,
                    "not_before": not_before_date.strftime('%Y-%m-%d %H:%M:%S'),
                    "not_after": not_after_date.strftime('%Y-%m-%d %H:%M:%S'),
                    "is_valid": is_valid,
                    "days_remaining": days_remaining,
                    "is_ca": is_ca,
                    "is_end_entity": is_end_entity
                }
            
            return {"error": "Could not find validity dates in certificate"}
        
    except Exception as e:
        return {"error": f"Error processing certificate: {str(e)}"}
    finally:
        # Clean up temporary file if it was created
        if cert_path.suffix.lower() in {'.jks', '.keystore'} and 'temp_p12' in locals():
            try:
                os.remove(temp_p12)
            except:
                pass

def try_password(cert_path: Path, password: str) -> bool:
    """
    Try to decrypt the certificate file using the given password.
    Returns True if successful, False otherwise.
    """
    # Create output path in same directory as input file
    output_path = cert_path.with_suffix('.decrypted.pem')
    
    try:
        # Handle JKS files differently (including .keystore files)
        if cert_path.suffix.lower() in {'.jks', '.keystore'}:
            success, temp_p12 = convert_jks_to_p12(cert_path, password)
            if not success:
                return False
            # If conversion succeeded, try to extract the private key and certificates
            cert_path = temp_p12
            try:
                # Use OpenSSL to extract both private key and certificates from the converted PKCS#12
                cmd = [
                    'openssl', 'pkcs12',
                    '-in', str(cert_path),
                    '-out', str(output_path),
                    '-nodes',  # Don't encrypt the private key in the output
                    '-passin', f'pass:{password}'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    # Get certificate information
                    cert_info = get_cert_info(cert_path, password)
                    print(f"\nSuccess! Password found for {cert_path}")
                    print(f"Password: {password}")
                    print(f"Decrypted file created at: {output_path}")
                    
                    # Print certificate validity information
                    if "error" in cert_info:
                        print(f"Certificate info: {cert_info['error']}")
                    else:
                        status = "Valid" if cert_info["is_valid"] else "EXPIRED"
                        print(f"Certificate Status: {status}")
                        print(f"Valid from: {cert_info['not_before']}")
                        print(f"Valid until: {cert_info['not_after']}")
                        if cert_info["is_valid"]:
                            print(f"Days remaining: {cert_info['days_remaining']}")
                    
                    return True
                # Delete the output file if password attempt failed
                if output_path.exists():
                    output_path.unlink()
            finally:
                # Clean up temporary file
                try:
                    os.remove(temp_p12)
                except:
                    pass
            return False
        
        # Handle other file types
        if cert_path.suffix.lower() in {'.pfx', '.p12'}:
            # PKCS#12 format - extract both private key and certificates
            cmd = [
                'openssl', 'pkcs12',
                '-in', str(cert_path),
                '-out', str(output_path),
                '-nodes',  # Don't encrypt the private key in the output
                '-passin', f'pass:{password}'
            ]
        else:
            # For encrypted .key and .pem files, we need to get the certificate separately
            # First extract the private key
            cmd = [
                'openssl', 'rsa',
                '-in', str(cert_path),
                '-out', str(output_path),
                '-passin', f'pass:{password}'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # Try to find and append the corresponding certificate
                cert_path_possible = cert_path.with_suffix('.crt')
                if cert_path_possible.exists():
                    with open(cert_path_possible, 'r') as cert_file:
                        with open(output_path, 'a') as out_file:
                            out_file.write('\n')
                            out_file.write(cert_file.read())
                else:
                    # If no .crt file, try .cer
                    cert_path_possible = cert_path.with_suffix('.cer')
                    if cert_path_possible.exists():
                        with open(cert_path_possible, 'r') as cert_file:
                            with open(output_path, 'a') as out_file:
                                out_file.write('\n')
                                out_file.write(cert_file.read())
        
        if cert_path.suffix.lower() not in {'.key', '.pem'}:  # Skip for .key/.pem as we already ran the command
            result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Get certificate information
            cert_info = get_cert_info(cert_path, password)
            print(f"\nSuccess! Password found for {cert_path}")
            print(f"Password: {password}")
            print(f"Decrypted file created at: {output_path}")
            
            # Print certificate validity information
            if "error" in cert_info:
                print(f"Certificate info: {cert_info['error']}")
            else:
                status = "Valid" if cert_info["is_valid"] else "EXPIRED"
                print(f"Certificate Status: {status}")
                print(f"Valid from: {cert_info['not_before']}")
                print(f"Valid until: {cert_info['not_after']}")
                if cert_info["is_valid"]:
                    print(f"Days remaining: {cert_info['days_remaining']}")
            
            return True
        
        # Delete the output file if password attempt failed
        if output_path.exists():
            output_path.unlink()
            
        return False
        
    except Exception as e:
        # Delete the output file if an error occurred
        if output_path.exists():
            output_path.unlink()
        print(f"Error processing {cert_path}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Attempt to crack encrypted certificate files using a password list')
    parser.add_argument('-d', '--directory', required=True, help='Directory to scan for certificate files')
    parser.add_argument('-p', '--password-list', required=True, help='Path to file containing passwords to try')
    parser.add_argument('-t', '--types', help='Comma-separated list of certificate types to scan (default: pfx,p12,jks,keystore). Use "key" or "pem" to include encrypted key files.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - suppress password attempt output for faster operation')
    args = parser.parse_args()
    
    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a valid directory")
        return
        
    # Validate password list
    if not os.path.isfile(args.password_list):
        print(f"Error: {args.password_list} is not a valid file")
        return
    
    # Handle certificate types if specified
    global CERT_EXTENSIONS
    if args.types is not None:
        requested_types = {f'.{ext.strip()}' for ext in args.types.split(',')}
        # Special handling for key, PEM, and JKS files
        if '.key' in requested_types:
            requested_types.remove('.key')
            # We'll handle key files separately in find_cert_files
        if '.pem' in requested_types:
            requested_types.remove('.pem')
            # We'll handle PEM files separately in find_cert_files
        if '.jks' in requested_types:
            requested_types.remove('.jks')
            # We'll handle JKS files separately in find_cert_files
        if '.keystore' in requested_types:
            requested_types.remove('.keystore')
            # We'll handle keystore files separately in find_cert_files
        valid_types = requested_types.intersection(CERT_EXTENSIONS)
        if not valid_types and '.key' not in args.types and '.pem' not in args.types and '.jks' not in args.types and '.keystore' not in args.types:
            print(f"Error: No valid certificate types specified. Supported types are: {', '.join(CERT_EXTENSIONS)},key,pem")
            return
        CERT_EXTENSIONS = valid_types
    
    # Find all certificate files
    print(f"\nScanning directory: {args.directory}")
    type_message = []
    if CERT_EXTENSIONS:
        type_message.append(f"certificate types: {', '.join(CERT_EXTENSIONS)}")
    if args.types is not None:
        if '.jks' in args.types or '.keystore' in args.types:
            type_message.append("JKS files")
        if '.key' in args.types:
            type_message.append("encrypted key files")
        if '.pem' in args.types:
            type_message.append("encrypted PEM files")
    print(f"Looking for {' and '.join(type_message)}")
    cert_files = find_cert_files(args.directory)
    
    if not cert_files:
        print("No certificate files found.")
        return
        
    print(f"Found {len(cert_files)} certificate files")
    
    # Read password list
    try:
        with open(args.password_list, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading password list: {str(e)}")
        return
        
    print(f"Loaded {len(passwords)} passwords to try")
    
    # Try each certificate file
    cracked_count = 0
    valid_certs = 0
    expired_certs = 0
    for cert_path in cert_files:
        if not args.quiet:
            print(f"\nTrying certificate file: {cert_path}")
        else:
            print(f"\nProcessing: {cert_path}")
        
        # Try each password
        for password in passwords:
            if not args.quiet:
                # Clear the line and print new password attempt
                print(f"\033[K", end='')  # ANSI escape sequence to clear the line
                print(f"Trying password: {password}", end='\r')
            if try_password(cert_path, password):
                cracked_count += 1
                # Get certificate info to track validity
                cert_info = get_cert_info(cert_path, password)
                if "error" not in cert_info:
                    if cert_info["is_valid"]:
                        valid_certs += 1
                    else:
                        expired_certs += 1
                # Stop trying passwords for this certificate file
                break
        else:
            if not args.quiet:
                print(f"\nNo password found for {cert_path}")
            else:
                print(f" - No password found")
            
    print(f"\nScan complete! {cracked_count} out of {len(cert_files)} certificate files were cracked.")
    if cracked_count > 0:
        print(f"Certificate validity summary:")
        print(f"  - Valid certificates: {valid_certs}")
        print(f"  - Expired certificates: {expired_certs}")
    print()  # Add extra newline at the end

if __name__ == "__main__":
    main() 