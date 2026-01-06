#!/usr/bin/env python3

# Secure TLS/SSL Server Implementation
# This server handles encrypted client connections, authenticates users,
# and logs all events for security monitoring

import socket      # For network communication
import ssl         # For TLS/SSL encryption
import json        # For parsing user credentials and auth data
import hashlib     # For password hashing (SHA-256)
import threading   # For handling multiple clients concurrently
import os
from datetime import datetime

class SecureServer:
    """
    Secure TLS server that:
    - Encrypts all communication with TLS 1.2+
    - Authenticates users with hashed passwords
    - Logs all events for security monitoring
    - Handles multiple clients using threading
    """

    def __init__(self, host='localhost', port=8443, cert_file='server.crt', key_file='server.key'):
        # Server configuration
        self.host = host
        self.port = port
        self.cert_file = cert_file  # SSL certificate path
        self.key_file = key_file    # Private key path
        self.users_file = 'users.json'  # User database
        self.log_file = 'server.log'    # Event log file
        self.users = self.load_users()  # Load user credentials
        self.running = True  # Server running state

    def load_users(self):
        """
        Load user credentials from JSON file.
        If file doesn't exist, create default users with hashed passwords.
        Returns: dict of {username: hashed_password}
        """
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.log_event('ERROR', f'Failed to load users: {e}')
                return {}
        else:
            # Create default users if no database exists
            default_users = {
                'admin': self.hash_password('admin123'),
                'user': self.hash_password('user123')
            }
            self.save_users(default_users)
            return default_users

    def save_users(self, users):
        """
        Save user credentials to JSON file.
        Users are stored as {username: hashed_password} pairs.
        """
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            self.log_event('ERROR', f'Failed to save users: {e}')

    def hash_password(self, password):
        """
        Hash password using SHA-256.
        Passwords are never stored in plain text.
        Returns: hex digest of hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, username, password):
        """
        Authenticate user by comparing hashed password.
        Args:
            username: username to check
            password: plain text password to verify
        Returns: True if authentication successful, False otherwise
        """
        if username in self.users:
            hashed = self.hash_password(password)
            return self.users[username] == hashed
        return False

    def log_event(self, event_type, message, client_addr=None):
        """
        Log security events with timestamp and client address.
        All events are written to both console and log file.
        Format: [timestamp] [ip:port] EVENT_TYPE: message
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Format address as IP:Port or 'SERVER' for internal events
        addr_str = f'{client_addr[0]}:{client_addr[1]}' if client_addr else 'SERVER'
        log_entry = f'[{timestamp}] [{addr_str}] {event_type}: {message}\n'

        # Output to console and file
        print(log_entry.strip())
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f'Logging error: {e}')

    def handle_client(self, conn, addr):
        """
        Handle an individual client connection in a separate thread.
        Process:
        1. Log connection
        2. Get TLS cipher information
        3. Receive and verify authentication
        4. Process messages if authenticated
        5. Log all events and disconnect
        """
        self.log_event('CONNECT', 'Client connected', addr)

        try:
            # Get SSL/TLS connection info for logging
            cipher = conn.cipher()
            if cipher:
                # Log cipher suite and protocol version
                self.log_event('TLS_INFO', f'Cipher: {cipher[0]}, Protocol: {cipher[1]}', addr)

            # Receive authentication data (JSON format)
            data = conn.recv(1024).decode('utf-8')
            if not data:
                self.log_event('AUTH_FAIL', 'No data received', addr)
                conn.sendall(b'ERROR:No authentication data')
                return

            try:
                # Parse authentication credentials
                auth_data = json.loads(data)
                username = auth_data.get('username')
                password = auth_data.get('password')

                # Verify credentials
                if self.authenticate(username, password):
                    self.log_event('AUTH_SUCCESS', f'User {username} authenticated', addr)
                    conn.sendall(b'AUTH:OK')

                    # Message loop - handle client messages after authentication
                    while True:
                        msg = conn.recv(1024).decode('utf-8')
                        if not msg or msg == 'QUIT':
                            break

                        # Log received message
                        self.log_event('MESSAGE', f'From {username}: {msg}', addr)

                        # Echo message back to client (encrypted)
                        response = f'Echo: {msg}'
                        conn.sendall(response.encode('utf-8'))

                        # Log sent response
                        self.log_event('RESPONSE', f'Sent to {username}: {response}', addr)
                else:
                    # Authentication failed
                    self.log_event('AUTH_FAIL', f'Invalid credentials for {username}', addr)
                    conn.sendall(b'ERROR:Invalid credentials')

            except json.JSONDecodeError:
                # Invalid JSON format in authentication data
                self.log_event('AUTH_FAIL', 'Invalid JSON format', addr)
                conn.sendall(b'ERROR:Invalid format')

        except Exception as e:
            # Log any errors during client handling
            self.log_event('ERROR', f'Client handling error: {e}', addr)

        finally:
            # Always close connection and log disconnect
            conn.close()
            self.log_event('DISCONNECT', 'Client disconnected', addr)

    def start(self):
        """
        Start the TLS server and listen for client connections.
        Process:
        1. Create SSL context with TLS 1.2+ requirement
        2. Load certificate and private key
        3. Create and bind socket
        4. Wrap socket with SSL/TLS
        5. Accept clients and spawn handler threads
        """
        # Create SSL context for TLS server
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)

        # Enforce minimum TLS version 1.2 for security
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        self.log_event('START', f'Server starting on {self.host}:{self.port}')

        # Create TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Allow port reuse to avoid "address already in use" errors
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to address and start listening
            sock.bind((self.host, self.port))
            sock.listen(5)  # Allow up to 5 queued connections

            self.log_event('LISTEN', f'Listening for connections')

            # Wrap socket with SSL/TLS
            with context.wrap_socket(sock, server_side=True) as ssock:
                # Main server loop - accept and handle clients
                while self.running:
                    try:
                        # Accept incoming client connection
                        conn, addr = ssock.accept()

                        # Handle each client in a separate thread
                        # This allows multiple concurrent clients
                        client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                        client_thread.start()

                    except KeyboardInterrupt:
                        # Graceful shutdown on Ctrl+C
                        self.log_event('STOP', 'Server shutting down')
                        self.running = False
                        break
                    except Exception as e:
                        # Log any accept errors
                        self.log_event('ERROR', f'Accept error: {e}')

# Main entry point
if __name__ == '__main__':
    server = SecureServer()
    try:
        server.start()
    except Exception as e:
        print(f'Server error: {e}')
