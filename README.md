# SNMPv3 Scanner

A web-based application for scanning network devices using SNMPv3 protocol. This application provides a simple and user-friendly interface to input IP addresses and SNMPv3 credentials, and displays the scan results in an organized manner.

## Features

- Scan network devices using SNMPv3 protocol
- Support for various authentication protocols (MD5, SHA, SHA224, SHA256, SHA384, SHA512)
- Support for privacy protocols (DES, 3DES, AES, AES192, AES256)
- View system information and network interfaces of scanned devices
- Asynchronous scanning with real-time status updates
- Clean and responsive Bootstrap UI

## Requirements

- Python 3.7+
- Flask
- pysnmp
- Flask-WTF
- Bootstrap-Flask

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/crpMaster/testing2files.git
   cd testing2files
   ```

2. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   ```
   
   On Windows:
   ```
   venv\Scripts\activate
   ```
   
   On macOS/Linux:
   ```
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

3. Enter the IP address and SNMPv3 credentials of the device you want to scan:
   - IP Address: The IP address of the network device
   - Username: SNMPv3 username
   - Auth Protocol: Authentication protocol (MD5, SHA, etc.)
   - Auth Password: Authentication password
   - Privacy Protocol: Privacy/encryption protocol (DES, AES, etc.)
   - Privacy Password: Privacy/encryption password

4. Click the "Scan Device" button to start scanning.

5. View the scan results in real-time. Results include:
   - System information (System Name, Description, Location, etc.)
   - Network interfaces details

## Troubleshooting

- Ensure the target device has SNMPv3 enabled and properly configured
- Verify the credentials are correct
- Check if the device is reachable from your network
- Ensure the required SNMP ports are not blocked by firewalls (default: UDP 161)

## Security Considerations

- The application uses form CSRF protection
- Authentication and privacy passwords are not stored between sessions
- Consider running the application behind a secure proxy in production environments
- Do not expose the application to public networks without proper security measures

## License

This project is open source and available under the MIT License. 