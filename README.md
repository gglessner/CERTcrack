# CERTcrack

A powerful tool for cracking passwords on various encrypted certificate file formats. CERTcrack supports multiple certificate store formats and can attempt to crack them using a provided password list.

## Supported File Types

### Default Search (No Additional Flags Required)
- `.pfx` (PKCS#12)
- `.p12` (PKCS#12)
- `.jks` (Java KeyStore)
- `.keystore` (Java KeyStore)

### Optional Search (Requires -t Flag)
- `.key` (Encrypted private keys)
- `.pem` (Encrypted private keys)

## Prerequisites

- Python 3.6 or higher
- OpenSSL
- Java Runtime Environment (JRE) with keytool (for JKS/keystore support)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/gglessner/CERTcrack.git
cd CERTcrack
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python CERTcrack.py -d /path/to/certs -p /path/to/passwords.txt
```

### Command Line Arguments

- `-d, --directory`: Directory to scan for certificate files (required)
- `-p, --password-list`: Path to file containing passwords to try (required)
- `-t, --types`: Comma-separated list of certificate types to scan (optional)
  - Default: pfx,p12,jks,keystore
  - Additional options: key,pem
- `-q, --quiet`: Enable quiet mode for faster operation (optional)
  - Suppresses password attempt output
  - Useful for large password lists or when running in background

### Examples

1. Search for all default certificate types:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt
```

2. Search for specific certificate types:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt -t pfx,key
```

3. Search only for encrypted key files:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt -t key,pem
```

4. Search only for Java keystores:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt -t jks,keystore
```

5. Run in quiet mode for faster operation:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt -q
```

6. Combine options:
```bash
python CERTcrack.py -d ./certificates -p ./passwords.txt -t pfx,key -q
```

## Output

The script will:
1. Scan the specified directory for supported certificate files
2. Report the number of files found
3. Attempt to crack each file using the provided password list
4. Print progress in real-time
5. Create decrypted files with the extension `.decrypted.pem` when successful
6. For successfully cracked certificates, display:
   - Certificate status (Valid/EXPIRED)
   - Valid from date
   - Valid until date
   - Days remaining (for valid certificates)
   - Certificate type (End-Entity or CA)
7. Provide a summary of cracked files at the end, including:
   - Total number of certificates cracked
   - Number of valid certificates
   - Number of expired certificates

Note: The script prioritizes end-entity certificates (client certificates used for authentication) over CA certificates when multiple certificates are present in a keystore. This ensures that the validity information shown is for the actual certificate being used for authentication rather than its CA certificate.

## Password List Format

The password list should be a text file with one password per line. For example:
```
password123
certpass
mysecret
company2023
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Author

Garland Glessner <gglessner@gmail.com>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is provided for legitimate security testing and recovery purposes only. Always ensure you have proper authorization before attempting to crack any certificate files. 