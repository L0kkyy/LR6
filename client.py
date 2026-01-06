#!/usr/bin/env python3

# Secure TLS/SSL Client Implementation
# This client connects to the TLS server, authenticates, and
# sends encrypted messages

import socket  # For network communication
import ssl     # For TLS/SSL encryption
import json    # For sending authentication credentials
import sys

class SecureClient:
    """
    Secure TLS client that:
    - Establishes encrypted connection to server
    - Verifies server certificate
    - Authenticates with username/password
    - Sends and receives encrypted messages
    - Displays connection and certificate details
    """

    def __init__(self, host='localhost', port=8443, cert_file='server.crt'):
        # Client configuration
        self.host = host
        self.port = port
        self.cert_file = cert_file  # Server's certificate for verification

    def connect(self, username, password):
        """
        Connect to TLS server and authenticate.
        Process:
        1. Create SSL context and load server certificate
        2. Establish TCP connection
        3. Wrap connection with TLS/SSL
        4. Display connection details
        5. Send authentication credentials
        6. Start interactive session if authenticated
        """
        # Create SSL context for client-side TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load server certificate to verify its identity
        # This prevents man-in-the-middle attacks
        context.load_verify_locations(self.cert_file)

        # Disable hostname checking for self-signed certificates
        # In production, you would verify the hostname matches the certificate
        context.check_hostname = False

        print(f'Connecting to {self.host}:{self.port}...')

        try:
            # Create TCP connection to server
            with socket.create_connection((self.host, self.port)) as sock:
                # Wrap socket with SSL/TLS encryption
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    # Display TLS connection information
                    print(f'SSL established. Protocol: {ssock.version()}')

                    # Get cipher suite information
                    cipher = ssock.cipher()
                    if cipher:
                        print(f'Cipher: {cipher[0]}')         # Cipher algorithm
                        print(f'TLS Version: {cipher[1]}')    # TLS protocol version
                        print(f'Bits: {cipher[2]}')           # Key strength in bits

                    # Get and display server certificate information
                    cert = ssock.getpeercert()
                    if cert:
                        print(f'\nCertificate Info:')
                        # Extract and display certificate subject (who the cert is issued to)
                        print(f'  Subject: {dict(x[0] for x in cert["subject"])}')
                        # Extract and display certificate issuer (who issued the cert)
                        print(f'  Issuer: {dict(x[0] for x in cert["issuer"])}')
                        # Display certificate validity period
                        print(f'  Not Before: {cert["notBefore"]}')
                        print(f'  Not After: {cert["notAfter"]}')

                    # Prepare authentication credentials
                    auth_data = {
                        'username': username,
                        'password': password
                    }

                    # Send credentials to server (encrypted by TLS)
                    print(f'\nAuthenticating as {username}...')
                    ssock.sendall(json.dumps(auth_data).encode('utf-8'))

                    # Receive authentication response from server
                    response = ssock.recv(1024).decode('utf-8')

                    if response == 'AUTH:OK':
                        # Authentication successful - start interactive session
                        print('Authentication successful!\n')
                        self.interactive_session(ssock)
                    else:
                        # Authentication failed - display error
                        print(f'Authentication failed: {response}')

        except ssl.SSLError as e:
            # Handle SSL/TLS specific errors (certificate issues, handshake failures, etc.)
            print(f'SSL Error: {e}')
        except ConnectionRefusedError:
            # Server is not running or not accepting connections
            print('Connection refused. Is the server running?')
        except Exception as e:
            # Handle any other errors
            print(f'Error: {e}')

    def interactive_session(self, ssock):
        """
        Interactive message session after successful authentication.
        User can type messages that are sent to server and echoed back.
        All messages are encrypted by TLS.
        Type 'quit' to disconnect.
        """
        print('Connected! Type messages to send to server (or "quit" to exit)')
        print('-' * 60)

        # Message loop
        while True:
            try:
                # Get message from user
                message = input('> ')
                if not message:
                    continue

                # Check for quit command
                if message.lower() == 'quit':
                    ssock.sendall(b'QUIT')
                    print('Disconnecting...')
                    break

                # Send message to server (encrypted by TLS)
                ssock.sendall(message.encode('utf-8'))

                # Receive and display server response (decrypted from TLS)
                response = ssock.recv(1024).decode('utf-8')
                print(f'Server: {response}')

            except KeyboardInterrupt:
                # Handle Ctrl+C gracefully
                print('\nDisconnecting...')
                ssock.sendall(b'QUIT')
                break
            except Exception as e:
                # Handle any errors during message exchange
                print(f'Error: {e}')
                break

def main():
    """
    Main entry point.
    Prompts user for credentials and connects to server.
    """
    print('=== Secure TLS Client ===\n')

    # Get credentials from user
    username = input('Username: ').strip()
    password = input('Password: ').strip()

    # Validate that credentials were provided
    if not username or not password:
        print('Username and password required')
        return

    # Create client and connect
    client = SecureClient()
    client.connect(username, password)

# Run main function when script is executed
if __name__ == '__main__':
    main()
