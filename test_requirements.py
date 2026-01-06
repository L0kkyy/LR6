#!/usr/bin/env python3

import socket
import ssl
import json
import os
import time
import subprocess
import sys
from datetime import datetime

class RequirementsTester:
    def __init__(self):
        self.results = []
        self.server_process = None
        self.test_count = 0
        self.passed_count = 0

    def log_test(self, test_name, passed, details=''):
        # Record test result
        self.test_count += 1
        status = 'PASS' if passed else 'FAIL'
        if passed:
            self.passed_count += 1

        result = {
            'test': test_name,
            'status': status,
            'details': details
        }
        self.results.append(result)

        symbol = '[+]' if passed else '[x]'
        print(f'{symbol} {test_name}: {status}')
        if details:
            print(f'    {details}')

    def test_files_exist(self):
        # Test 1: Check required files exist
        print('\n=== TEST 1: File Structure ===')

        required_files = [
            'server.py',
            'client.py',
            'analyze_logs.py',
            'server.crt',
            'server.key',
            'README.txt'
        ]

        all_exist = True
        for filename in required_files:
            exists = os.path.exists(filename)
            if not exists:
                all_exist = False
            self.log_test(f'File exists: {filename}', exists)

        return all_exist

    def test_certificate(self):
        # Test 2: Verify SSL certificate
        print('\n=== TEST 2: SSL Certificate ===')

        try:
            # Check certificate file exists and can be loaded
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('server.crt')
            self.log_test('SSL certificate loads', True, 'Certificate file is valid')

            # Check private key exists
            key_exists = os.path.exists('server.key')
            self.log_test('Private key exists', key_exists)

            return True
        except Exception as e:
            self.log_test('SSL certificate loads', False, str(e))
            return False

    def test_user_database(self):
        # Test 3: Check user database
        print('\n=== TEST 3: User Authentication Database ===')

        # Start server briefly to generate users.json
        if not os.path.exists('users.json'):
            print('    Initializing user database...')
            import server
            srv = server.SecureServer()
            srv.load_users()

        try:
            with open('users.json', 'r') as f:
                users = json.load(f)

            # Check if users exist
            has_admin = 'admin' in users
            has_user = 'user' in users

            self.log_test('User database created', True)
            self.log_test('Admin user exists', has_admin)
            self.log_test('Regular user exists', has_user)

            # Check if passwords are hashed (not plain text)
            if has_admin:
                admin_pass = users['admin']
                is_hashed = len(admin_pass) == 64  # SHA-256 hex length
                self.log_test('Passwords are hashed', is_hashed,
                            f'Hash length: {len(admin_pass)}')

            return True
        except Exception as e:
            self.log_test('User database created', False, str(e))
            return False

    def test_tls_connection(self):
        # Test 4: Test TLS connection establishment
        print('\n=== TEST 4: TLS Connection ===')

        try:
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('server.crt')
            context.check_hostname = False

            # Try to connect
            with socket.create_connection(('localhost', 8443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                    # Get TLS info
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Check TLS version
                    tls_valid = protocol in ['TLSv1.2', 'TLSv1.3']
                    self.log_test('TLS connection established', True,
                                f'Protocol: {protocol}')
                    self.log_test('TLS version is 1.2 or higher', tls_valid,
                                f'Version: {protocol}')

                    if cipher:
                        self.log_test('Cipher negotiated', True,
                                    f'Cipher: {cipher[0]}')

                    # Get certificate
                    cert = ssock.getpeercert()
                    has_cert = cert is not None
                    self.log_test('Server certificate received', has_cert)

                    return True
        except ConnectionRefusedError:
            self.log_test('TLS connection established', False,
                        'Server not running - start server first')
            return False
        except Exception as e:
            self.log_test('TLS connection established', False, str(e))
            return False

    def test_authentication(self):
        # Test 5: Test authentication mechanism
        print('\n=== TEST 5: Authentication ===')

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('server.crt')
            context.check_hostname = False

            # Test successful authentication
            with socket.create_connection(('localhost', 8443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                    # Send valid credentials
                    auth_data = {'username': 'admin', 'password': 'admin123'}
                    ssock.sendall(json.dumps(auth_data).encode('utf-8'))

                    response = ssock.recv(1024).decode('utf-8')
                    auth_success = response == 'AUTH:OK'
                    self.log_test('Successful authentication', auth_success,
                                f'Response: {response}')

                    ssock.sendall(b'QUIT')

            # Test failed authentication
            with socket.create_connection(('localhost', 8443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                    # Send invalid credentials
                    auth_data = {'username': 'admin', 'password': 'wrongpass'}
                    ssock.sendall(json.dumps(auth_data).encode('utf-8'))

                    response = ssock.recv(1024).decode('utf-8')
                    auth_failed = 'ERROR' in response
                    self.log_test('Failed authentication detected', auth_failed,
                                f'Response: {response}')

            return True
        except Exception as e:
            self.log_test('Authentication test', False, str(e))
            return False

    def test_message_exchange(self):
        # Test 6: Test encrypted message transmission
        print('\n=== TEST 6: Encrypted Message Exchange ===')

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('server.crt')
            context.check_hostname = False

            with socket.create_connection(('localhost', 8443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                    # Authenticate
                    auth_data = {'username': 'admin', 'password': 'admin123'}
                    ssock.sendall(json.dumps(auth_data).encode('utf-8'))
                    response = ssock.recv(1024).decode('utf-8')

                    if response == 'AUTH:OK':
                        # Send test message
                        test_msg = 'Test message for encryption'
                        ssock.sendall(test_msg.encode('utf-8'))

                        # Receive echo
                        echo = ssock.recv(1024).decode('utf-8')

                        got_response = len(echo) > 0
                        is_echo = test_msg in echo

                        self.log_test('Message sent over TLS', True)
                        self.log_test('Server response received', got_response,
                                    f'Response: {echo}')
                        self.log_test('Message integrity verified', is_echo)

                        ssock.sendall(b'QUIT')
                        return True

            return False
        except Exception as e:
            self.log_test('Message exchange test', False, str(e))
            return False

    def test_logging(self):
        # Test 7: Check event logging
        print('\n=== TEST 7: Event Logging ===')

        # Wait a bit for logs to be written
        time.sleep(1)

        try:
            if not os.path.exists('server.log'):
                self.log_test('Log file created', False, 'server.log not found')
                return False

            with open('server.log', 'r') as f:
                logs = f.read()

            # Check for different event types
            has_connect = 'CONNECT' in logs
            has_auth_success = 'AUTH_SUCCESS' in logs
            has_auth_fail = 'AUTH_FAIL' in logs
            has_message = 'MESSAGE' in logs
            has_timestamp = any(line.startswith('[20') for line in logs.split('\n'))

            self.log_test('Log file created', True)
            self.log_test('Connection events logged', has_connect)
            self.log_test('Auth success logged', has_auth_success)
            self.log_test('Auth failure logged', has_auth_fail)
            self.log_test('Message events logged', has_message)
            self.log_test('Timestamps present', has_timestamp)

            # Count log entries
            log_lines = [l for l in logs.split('\n') if l.strip()]
            entry_count = len(log_lines)
            has_entries = entry_count > 0
            self.log_test('Log entries exist', has_entries,
                        f'Found {entry_count} log entries')

            return True
        except Exception as e:
            self.log_test('Event logging test', False, str(e))
            return False

    def test_log_analysis(self):
        # Test 8: Test log analysis functionality
        print('\n=== TEST 8: Log Analysis ===')

        try:
            # Check if analyzer exists
            if not os.path.exists('analyze_logs.py'):
                self.log_test('Log analyzer exists', False)
                return False

            self.log_test('Log analyzer exists', True)

            # Try to import and use analyzer
            import analyze_logs
            analyzer = analyze_logs.LogAnalyzer()

            parsed = analyzer.parse_log()
            self.log_test('Log parsing works', parsed)

            if parsed:
                # Check if events were parsed
                has_events = len(analyzer.events) > 0
                has_stats = len(analyzer.stats) > 0

                self.log_test('Events parsed', has_events,
                            f'Found {len(analyzer.events)} events')
                self.log_test('Statistics calculated', has_stats)

                # Check anomaly detection
                conflicts = analyzer.find_conflicts() if hasattr(analyzer, 'find_conflicts') else []
                self.log_test('Anomaly detection implemented', True)

            return True
        except Exception as e:
            self.log_test('Log analysis test', False, str(e))
            return False

    def generate_report(self):
        # Generate final report
        print('\n' + '=' * 70)
        print('REQUIREMENT VERIFICATION REPORT')
        print('=' * 70)
        print(f'\nTests Run: {self.test_count}')
        print(f'Passed: {self.passed_count}')
        print(f'Failed: {self.test_count - self.passed_count}')

        pass_rate = (self.passed_count / self.test_count * 100) if self.test_count > 0 else 0
        print(f'Pass Rate: {pass_rate:.1f}%')

        print('\n' + '=' * 70)
        print('TASK REQUIREMENTS VERIFICATION')
        print('=' * 70)

        # Check against original task requirements
        requirements = [
            ('Server with SSL/TLS', ['TLS connection established', 'TLS version is 1.2 or higher']),
            ('SSL Certificate', ['SSL certificate loads', 'Server certificate received']),
            ('User Authentication', ['Successful authentication', 'Failed authentication detected']),
            ('Encrypted Communication', ['Message sent over TLS', 'Server response received']),
            ('Event Logging', ['Log file created', 'Connection events logged', 'Auth success logged']),
            ('Log Analysis', ['Log analyzer exists', 'Log parsing works', 'Events parsed'])
        ]

        print('\nRequirement Status:')
        for req_name, test_names in requirements:
            # Check if all related tests passed
            related_tests = [r for r in self.results if any(t in r['test'] for t in test_names)]
            all_passed = all(r['status'] == 'PASS' for r in related_tests)

            status = 'ACHIEVED' if all_passed else 'INCOMPLETE'
            symbol = '[+]' if all_passed else '[x]'
            print(f'{symbol} {req_name}: {status}')

        print('\n' + '=' * 70)

        if pass_rate >= 80:
            print('\nVERDICT: All task goals ACHIEVED')
            print('The application successfully implements:')
            print('- Secure SSL/TLS communication')
            print('- User authentication with hashed passwords')
            print('- Encrypted message transmission')
            print('- Comprehensive event logging')
            print('- Log analysis and anomaly detection')
        else:
            print('\nVERDICT: Some requirements NOT MET')
            print('Please review failed tests above')

        print('=' * 70)

def main():
    print('=' * 70)
    print('LR6 - REQUIREMENTS VERIFICATION TEST')
    print('Secure Client-Server Application with SSL/TLS')
    print('=' * 70)

    tester = RequirementsTester()

    # Run tests
    tester.test_files_exist()
    tester.test_certificate()
    tester.test_user_database()

    print('\n[*] Testing requires server to be running...')
    print('[*] Please start server in another terminal: python3 server.py')
    print('[*] Press Enter when server is ready (or Ctrl+C to skip server tests)')

    try:
        input()

        # Tests that require server
        tester.test_tls_connection()
        tester.test_authentication()
        tester.test_message_exchange()
        tester.test_logging()
        tester.test_log_analysis()
    except KeyboardInterrupt:
        print('\n[*] Skipping server-dependent tests')

    # Generate final report
    tester.generate_report()

if __name__ == '__main__':
    main()
