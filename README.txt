================================================================================
                SECURE CLIENT-SERVER APPLICATION WITH SSL/TLS
                              LR6 Project
================================================================================

OVERVIEW
--------
This project implements a secure client-server application using SSL/TLS
encryption for network communication. It includes user authentication,
encrypted data transmission, and comprehensive event logging.

Features:
- SSL/TLS encrypted communication (TLS 1.2+)
- User authentication with hashed passwords (SHA-256)
- Secure message transmission
- Comprehensive event logging
- Log analysis for anomaly detection
- Self-signed SSL certificates


FILES
-----
server.py         - TLS server with authentication
client.py         - TLS client for secure communication
analyze_logs.py   - Log analysis tool
server.crt        - SSL certificate (self-signed)
server.key        - SSL private key
users.json        - User credentials (auto-generated)
server.log        - Event log (auto-generated)
README.txt        - This file


REQUIREMENTS
------------
- Python 3.6 or higher
- OpenSSL (for certificate generation)
- Standard Python libraries: ssl, socket, json, hashlib, threading


QUICK START
-----------

1. Start the server:
   python3 server.py

2. In another terminal, start the client:
   python3 client.py

3. Login with default credentials:
   Username: admin
   Password: admin123

   or

   Username: user
   Password: user123

4. Send messages and see them echoed back encrypted

5. Analyze logs:
   python3 analyze_logs.py


DETAILED USAGE
--------------

SERVER
------
The server listens on port 8443 (default HTTPS alternative port) and
handles multiple clients using threading.

Start server:
    python3 server.py

The server will:
- Load or create SSL certificates (server.crt, server.key)
- Load or create user database (users.json)
- Listen for TLS connections on localhost:8443
- Authenticate clients
- Echo received messages
- Log all events to server.log


CLIENT
------
The client connects to the server using TLS and authenticates.

Start client:
    python3 client.py

You will be prompted for:
- Username
- Password

After successful authentication, you can:
- Send text messages
- Receive encrypted responses
- Type "quit" to disconnect

The client displays:
- TLS protocol version
- Cipher information
- Certificate details
- Connection status


LOG ANALYSIS
------------
Analyze server logs for security issues and anomalies.

Run analysis:
    python3 analyze_logs.py

The analyzer provides:
- Event statistics
- Authentication success rates
- Anomaly detection (failed auth attempts, errors, etc.)
- Connection timeline
- Security recommendations


AUTHENTICATION
--------------

Default Users:
  Username: admin  | Password: admin123
  Username: user   | Password: user123

Passwords are hashed using SHA-256 before storage.

The users.json file format:
{
  "username": "hashed_password_sha256"
}

To add a new user, you can manually edit users.json with a hashed password,
or modify the server code to include a user registration function.


SSL/TLS DETAILS
---------------

Certificate Information:
- Type: Self-signed X.509
- Key Size: 2048-bit RSA
- Validity: 365 days
- Subject: CN=localhost

TLS Configuration:
- Minimum Protocol: TLS 1.2
- Cipher Suites: System default (strong ciphers)
- Certificate Verification: Enabled (using server.crt)

The server uses Python's ssl module with secure defaults.


SECURITY FEATURES
-----------------

1. ENCRYPTION
   - All communication encrypted with TLS
   - Strong cipher suites
   - Minimum TLS 1.2 protocol

2. AUTHENTICATION
   - Username/password based
   - Passwords hashed with SHA-256
   - Failed attempts logged

3. LOGGING
   - All connections logged
   - Authentication attempts tracked
   - Message transmission recorded
   - Timestamps for all events

4. ANOMALY DETECTION
   - Failed authentication monitoring
   - Error rate tracking
   - Connection pattern analysis


EVENT LOG FORMAT
----------------

Log entries follow this format:
[TIMESTAMP] [ADDRESS] EVENT_TYPE: Message

Example:
[YYYY-MM-DD 14:00:00] [127.0.0.1:54321] AUTH_SUCCESS: User admin authenticated

Event Types:
- START:        Server startup
- LISTEN:       Server listening for connections
- CONNECT:      Client connected
- TLS_INFO:     TLS connection details
- AUTH_SUCCESS: Successful authentication
- AUTH_FAIL:    Failed authentication
- MESSAGE:      Message received from client
- RESPONSE:     Response sent to client
- DISCONNECT:   Client disconnected
- ERROR:        Error occurred
- STOP:         Server shutdown


LOG ANALYSIS FEATURES
---------------------

The log analyzer detects:

HIGH SEVERITY:
- Multiple failed authentication attempts
- Very low authentication success rate (<50%)
- Repeated failures from same IP

MEDIUM SEVERITY:
- SSL/TLS errors
- General errors in operation
- Moderate authentication failure rate

The analyzer provides:
- Event statistics and counts
- Authentication success rates
- IP-based failure tracking
- Connection timeline
- Security recommendations


TESTING THE APPLICATION
------------------------

Test 1: Successful Connection
------------------------------
1. Start server: python3 server.py
2. Start client: python3 client.py
3. Login as: admin / admin123
4. Send message: Hello Server
5. Verify encrypted echo response
6. Check server.log for events

Test 2: Failed Authentication
------------------------------
1. Start server
2. Start client
3. Login with wrong password
4. Verify authentication failure
5. Check server.log for AUTH_FAIL event

Test 3: Multiple Clients
-------------------------
1. Start server
2. Start multiple client instances
3. Login with different users
4. Send messages from each
5. Verify all clients work independently

Test 4: Log Analysis
--------------------
1. Perform tests 1-3
2. Run: python3 analyze_logs.py
3. Review statistics and anomalies
4. Check recommendations


ENCRYPTION SESSION DETAILS
---------------------------

When a client connects, the following occurs:

1. TCP Connection
   - Client connects to server:8443

2. TLS Handshake
   - Client hello / Server hello
   - Certificate exchange
   - Key exchange
   - Cipher suite negotiation

3. Certificate Verification
   - Client verifies server certificate
   - Uses server.crt as trust anchor

4. Encrypted Channel Established
   - Session keys derived
   - All further communication encrypted

5. Authentication
   - Client sends credentials (encrypted)
   - Server verifies against users.json

6. Secure Communication
   - Messages encrypted in transit
   - Server responds with encrypted echo


TROUBLESHOOTING
---------------

Issue: Connection refused
Solution: Ensure server is running on correct port (8443)

Issue: SSL certificate verify failed
Solution: Ensure client has access to server.crt file

Issue: Authentication failed
Solution: Check username/password against users.json

Issue: Permission denied on port 8443
Solution: Use a different port or run with appropriate permissions

Issue: Certificate expired
Solution: Regenerate certificate with new expiry date


SECURITY CONSIDERATIONS
-----------------------

This is an EDUCATIONAL project demonstrating SSL/TLS concepts.

For production use, consider:
- Use proper CA-signed certificates (not self-signed)
- Implement stronger password hashing (bcrypt, scrypt, argon2)
- Add rate limiting for failed authentication
- Implement IP blocking after multiple failures
- Use proper secret management
- Add input validation and sanitization
- Implement session management
- Add encryption at rest for user database
- Use environment variables for sensitive config
- Implement proper error handling
- Add audit logging with tamper protection


MODIFYING THE APPLICATION
--------------------------

Change Server Port:
Edit server.py, modify: port=8443 to desired port
Edit client.py to match

Add New User:
Option 1: Edit users.json manually with hashed password
Option 2: Modify server.py to add registration function

Change Certificate:
Regenerate using:
  openssl req -x509 -newkey rsa:2048 -keyout server.key \
    -out server.crt -days 365 -nodes -subj "/CN=localhost"

Enable File Transfer:
Modify client/server to send/receive binary data
Update message handling to support file mode


TECHNICAL ARCHITECTURE
-----------------------

Server Architecture:
- Main thread: Accept connections
- Worker threads: Handle individual clients
- Shared resources: users.json, server.log (thread-safe)

Client Architecture:
- Single-threaded
- Interactive session after authentication
- Synchronous request/response

Security Flow:
1. TLS handshake (encryption established)
2. Authentication (credentials verified)
3. Message exchange (encrypted communication)
4. Logging (all events recorded)
5. Graceful disconnect

Threading Model:
- Server: One thread per client connection
- Thread-safe logging with file locks
- Clean shutdown on SIGINT


ABOUT
-----
Created for LR6 - Secure Client-Server Application with SSL/TLS
Educational project for learning network security and encryption
