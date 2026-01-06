#!/usr/bin/env python3

# Log Analysis Tool for Security Monitoring
# Analyzes server logs to detect security issues, authentication
# failures, and potential attacks

import re  # For parsing log entries with regex
from collections import defaultdict  # For counting event types
from datetime import datetime

class LogAnalyzer:
    """
    Analyzes server logs to provide:
    - Event statistics and counts
    - Authentication success/failure rates
    - Anomaly detection (suspicious patterns)
    - IP-based failure tracking
    - Security recommendations
    """

    def __init__(self, log_file='server.log'):
        self.log_file = log_file
        self.events = []  # List of all parsed events
        self.stats = defaultdict(int)  # Count of each event type
        self.auth_failures = []  # List of failed auth attempts
        self.connections = []  # List of connection events

    def parse_log(self):
        """
        Parse log file and extract structured event data.
        Log format: [timestamp] [ip:port] EVENT_TYPE: message

        Returns: True if parsing successful, False otherwise
        """
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # Parse log entry using regex
                    # Captures: timestamp, address (IP:port), event type, message
                    match = re.match(r'\[(.*?)\] \[(.*?)\] (.*?): (.*)', line)
                    if match:
                        timestamp, address, event_type, message = match.groups()

                        # Create structured event dictionary
                        event = {
                            'timestamp': timestamp,
                            'address': address,
                            'type': event_type,
                            'message': message.strip()
                        }

                        # Add to events list
                        self.events.append(event)

                        # Count occurrences of each event type
                        self.stats[event_type] += 1

                        # Track specific event types for detailed analysis
                        if event_type == 'AUTH_FAIL':
                            self.auth_failures.append(event)
                        elif event_type == 'CONNECT':
                            self.connections.append(event)

        except FileNotFoundError:
            print(f'Log file {self.log_file} not found')
            return False
        except Exception as e:
            print(f'Error parsing log: {e}')
            return False

        return True

    def analyze(self):
        """
        Perform comprehensive log analysis.
        Generates report with:
        - Event statistics
        - Connection analysis
        - Anomaly detection
        - Security recommendations
        """
        print('=' * 70)
        print('LOG ANALYSIS REPORT')
        print('=' * 70)

        if not self.events:
            print('No events found in log file')
            return

        # Display total event count
        print(f'\nTotal Events: {len(self.events)}')

        # Display breakdown by event type
        print(f'\nEvent Breakdown:')
        for event_type, count in sorted(self.stats.items()):
            print(f'  {event_type:15s}: {count}')

        # Analyze connection patterns
        print(f'\n\nCONNECTION ANALYSIS')
        print('-' * 70)
        print(f'Total connections: {self.stats.get("CONNECT", 0)}')
        print(f'Successful authentications: {self.stats.get("AUTH_SUCCESS", 0)}')
        print(f'Failed authentications: {self.stats.get("AUTH_FAIL", 0)}')

        # Calculate and display authentication success rate
        total_auth = self.stats.get("AUTH_SUCCESS", 0) + self.stats.get("AUTH_FAIL", 0)
        if total_auth > 0:
            success_rate = (self.stats.get("AUTH_SUCCESS", 0) / total_auth) * 100
            print(f'Authentication success rate: {success_rate:.1f}%')

        # Anomaly Detection Section
        print(f'\n\nANOMALY DETECTION')
        print('-' * 70)

        anomalies_found = False

        # Check for repeated authentication failures (potential brute force attack)
        if self.stats.get("AUTH_FAIL", 0) > 3:
            print(f'[!] HIGH: {self.stats["AUTH_FAIL"]} authentication failures detected')
            anomalies_found = True

            # Track failures by IP address to identify attackers
            ip_failures = defaultdict(int)
            for failure in self.auth_failures:
                ip_failures[failure['address']] += 1

            # Display failure breakdown by IP
            print('    Failed authentication attempts by IP:')
            for ip, count in sorted(ip_failures.items(), key=lambda x: x[1], reverse=True):
                print(f'      {ip}: {count} attempts')

        # Check for TLS/SSL related errors
        tls_errors = [e for e in self.events if 'SSL' in e['message'] or 'TLS' in e['message']]
        if tls_errors:
            print(f'[!] MEDIUM: {len(tls_errors)} TLS/SSL related events')
            # Show first 3 TLS errors for review
            for err in tls_errors[:3]:
                print(f'      [{err["timestamp"]}] {err["message"]}')
            anomalies_found = True

        # Check for general errors
        errors = self.stats.get("ERROR", 0)
        if errors > 0:
            print(f'[!] MEDIUM: {errors} errors logged')
            anomalies_found = True

        # Check if authentication success rate is suspiciously low
        if total_auth > 0 and success_rate < 50:
            print(f'[!] HIGH: Low authentication success rate ({success_rate:.1f}%)')
            anomalies_found = True

        # Display if no anomalies found
        if not anomalies_found:
            print('[OK] No significant anomalies detected')

        # Display connection timeline (first 10 connections)
        print(f'\n\nCONNECTION TIMELINE')
        print('-' * 70)
        for conn in self.connections[:10]:
            print(f'[{conn["timestamp"]}] {conn["address"]} - {conn["message"]}')

        if len(self.connections) > 10:
            print(f'... and {len(self.connections) - 10} more connections')

        # Provide security recommendations based on findings
        print(f'\n\nRECOMMENDATIONS')
        print('-' * 70)

        if self.stats.get("AUTH_FAIL", 0) > 5:
            print('- Consider implementing rate limiting for failed authentication attempts')
            print('- Review and potentially block IPs with multiple failed attempts')

        if errors > 2:
            print('- Investigate error causes and fix underlying issues')

        if success_rate < 70 and total_auth > 0:
            print('- Review authentication mechanism for potential issues')

        if not anomalies_found and self.stats.get("AUTH_SUCCESS", 0) > 0:
            print('- System appears to be operating normally')
            print('- Continue monitoring for any changes')

        print('\n' + '=' * 70)

def main():
    """
    Main entry point.
    Creates analyzer, parses logs, and generates report.
    """
    analyzer = LogAnalyzer()
    if analyzer.parse_log():
        analyzer.analyze()

# Run main function when script is executed
if __name__ == '__main__':
    main()
