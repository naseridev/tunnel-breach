#!/usr/bin/env python3

import socket
import signal
import random
import re
import threading
import platform
import argparse
import logging
import sys
import os
from time import strftime, localtime, sleep
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
import contextlib
from typing import Tuple, Optional

class Tunnelbreach:

    DEFAULT_PORT = 22
    STAT_INTERVAL = 5
    CONSOLE_DATA_MAX_LENGTH = 80
    MAX_THREAD_WORKERS = 20
    MAX_CONNECTIONS = 100
    CONNECTION_TIMEOUT = 5
    MAX_LOG_SIZE = 10 * 1024 * 1024
    MAX_LOG_FILES = 5

    SSH_BANNERS = [
        b'SSH-2.0-OpenSSH_7.4p1 Debian-10',
        b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
        b'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3',
        b'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13',
        b'SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.10'
    ]

    SSH_RESPONSES = [
        b'Permission denied, please try again.',
        b'Access denied. This connection attempt has been logged.',
        b'Password incorrect. 2 attempts remaining before lockout.',
        b'Authentication failed. All connection attempts are monitored.',
        b'Warning: Unauthorized access is prohibited. This system is monitored.'
    ]

    def __init__(self, port: Optional[int] = None, stealth_mode: bool = False, max_workers: Optional[int] = None, max_connections: Optional[int] = None) -> None:
        self.port = port if port is not None else self.DEFAULT_PORT
        self.verbose = not stealth_mode
        self.running = False
        self.connections_logged = 0
        self.attacker_ips = {}
        self.banner = random.choice(self.SSH_BANNERS)
        self.response = random.choice(self.SSH_RESPONSES)
        self.max_workers = max_workers if max_workers is not None else self.MAX_THREAD_WORKERS
        self.max_connections = max_connections if max_connections is not None else self.MAX_CONNECTIONS
        self.connection_semaphore = threading.Semaphore(self.max_connections)
        self.lock = threading.Lock()

        self.setup_terminal_colors()
        self.setup_logging()

    def setup_terminal_colors(self) -> None:
        self.colors_enabled = True

        if os.environ.get('NO_COLOR') is not None:
            self.colors_enabled = False
        elif platform.system() == 'Windows':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception as e:
                self.colors_enabled = False
                logging.warning(f'Could not enable colors on Windows terminal: {e}')

        self.COLOR_BLUE = '\033[94m' if self.colors_enabled else ''
        self.COLOR_RED = '\033[91m' if self.colors_enabled else ''
        self.COLOR_GREEN = '\033[92m' if self.colors_enabled else ''
        self.COLOR_YELLOW = '\033[93m' if self.colors_enabled else ''
        self.COLOR_PURPLE = '\033[95m' if self.colors_enabled else ''
        self.COLOR_RESET = '\033[0m' if self.colors_enabled else ''

    def setup_logging(self) -> None:
        self.log_dir = Path(__file__).parent / '_logs'
        self.log_dir.mkdir(exist_ok=True)

        timestamp = strftime('%Y%m%d_%H%M%S', localtime())
        self.log_file = self.log_dir / f'honeypot_{timestamp}.log'

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        file_handler = RotatingFileHandler(
            filename=self.log_file,
            maxBytes=self.MAX_LOG_SIZE,
            backupCount=self.MAX_LOG_FILES,
            encoding='utf-8'
        )

        file_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)

        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        logging.info('Honeypot Started')
        logging.info(f'Listening on port {self.port}')
        logging.info(f'Max concurrent connections: {self.max_connections}')
        logging.info(f'Thread pool size: {self.max_workers}')

        self.print_status(f'Log file created: {self.log_file}', 'success')

    def print_status(self, message: str, message_type: str = 'info') -> None:
        if message_type == 'info':
            prefix = '[*]'
            color = self.COLOR_BLUE
            if self.verbose:
                print(f'{color}{prefix}{self.COLOR_RESET} {message}')

        elif message_type == 'error':
            prefix = '[!]'
            color = self.COLOR_RED
            print(f'{color}{prefix}{self.COLOR_RESET} {message}', file=sys.stderr)

        elif message_type == 'success':
            prefix = '[+]'
            color = self.COLOR_GREEN
            if self.verbose:
                print(f'{color}{prefix}{self.COLOR_RESET} {message}')

        elif message_type == 'warning':
            prefix = '[~]'
            color = self.COLOR_YELLOW
            if self.verbose:
                print(f'{color}{prefix}{self.COLOR_RESET} {message}')

        elif message_type == 'connection':
            prefix = '[C]'
            color = self.COLOR_PURPLE
            print(f'{color}{prefix}{self.COLOR_RESET} {message}')

    def sanitize_log_data(self, data_str: Optional[str]) -> str:
        if not data_str:
            return ''

        sanitized = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', data_str)

        max_length = 1000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '... (truncated)'

        return sanitized

    def log_connection(self, ip: str, port: int, data: Optional[bytes] = None) -> None:
        with self.lock:
            self.connections_logged += 1
            if ip in self.attacker_ips:
                self.attacker_ips[ip] += 1
            else:
                self.attacker_ips[ip] = 1

        log_entry = f'Connection from {ip}:{port} (Attempt #{self.attacker_ips[ip]})'
        display_entry = log_entry

        clean_data = ''

        if data:
            try:
                decoded_data = data.decode('utf-8', errors='ignore').strip()
                clean_data = self.sanitize_log_data(decoded_data)

                if clean_data:
                    log_entry += f' - Data: {clean_data}'

                    if len(clean_data) > self.CONSOLE_DATA_MAX_LENGTH:
                        truncated_data = clean_data[:self.CONSOLE_DATA_MAX_LENGTH] + '...'
                        display_entry += f' - Data: {truncated_data}'
                    else:
                        display_entry += f' - Data: {clean_data}'
            except Exception as e:
                logging.error(f'Error processing data from {ip}:{port}: {e}')

        logging.info(log_entry)
        self.print_status(display_entry, 'connection')

        if self.connections_logged % self.STAT_INTERVAL == 0:
            self.print_statistics()

    def print_statistics(self) -> None:
        if not self.verbose:
            return

        self.print_status('-' * 60, 'info')
        self.print_status('STATISTICS UPDATE', 'warning')
        self.print_status(f'Total connections logged: {self.connections_logged}', 'info')

        if self.attacker_ips:
            top_attackers = sorted(self.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            self.print_status('Top 5 attackers:', 'warning')
            for i, (ip, count) in enumerate(top_attackers, 1):
                self.print_status(f'  {i}. {ip:15} - {count} attempts', 'info')

        self.print_status(f'Unique IPs detected: {len(self.attacker_ips)}', 'info')
        self.print_status('-' * 60, 'info')

    def handle_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        acquired = self.connection_semaphore.acquire(blocking=False)
        if not acquired:
            logging.warning(f'Connection limit reached, rejecting connection from {client_address}')
            try:
                client_socket.close()
            except Exception:
                pass
            return

        try:
            ip, port = client_address
            self.log_connection(ip, port)

            sleep(random.uniform(0.1, 0.5))
            client_socket.sendall(self.banner + b'\r\n')

            try:
                client_socket.settimeout(self.CONNECTION_TIMEOUT)
                data = client_socket.recv(1024)
                if data:
                    self.log_connection(ip, port, data)
            except (socket.timeout, socket.error) as e:
                logging.debug(f'Error receiving initial data from {ip}:{port}: {e}')

            sleep(random.uniform(0.5, 2.0))
            try:
                client_socket.sendall(self.response + b'\r\n')
            except (socket.timeout, socket.error) as e:
                logging.debug(f'Error sending response to {ip}:{port}: {e}')

            for _ in range(random.randint(1, 2)):
                try:
                    client_socket.settimeout(self.CONNECTION_TIMEOUT)
                    data = client_socket.recv(1024)
                    if data:
                        self.log_connection(ip, port, data)
                        sleep(random.uniform(0.5, 1.5))
                        client_socket.sendall(random.choice(self.SSH_RESPONSES) + b'\r\n')
                except (socket.timeout, socket.error) as e:
                    logging.debug(f'Error during further communication with {ip}:{port}: {e}')
                    break

            sleep(random.uniform(0.3, 1.0))

        except Exception as e:
            self.print_status(f'Connection error from {client_address}: {e}', 'error')
            logging.error(f'Connection handler error from {client_address}: {e}')
        finally:
            try:
                client_socket.close()
            except Exception as e:
                logging.debug(f'Error closing client socket from {client_address}: {e}')
            self.connection_semaphore.release()

    def print_summary(self, start_time: datetime, runtime_str: str) -> None:
        if self.verbose:
            print()

        self.print_status('-' * 70, 'warning')
        self.print_status('HONEYPOT SESSION SUMMARY', 'success')
        self.print_status(f'Started: {start_time.strftime("%Y-%m-%d %H:%M:%S")}', 'info')
        self.print_status(f'Duration: {runtime_str}', 'info')
        self.print_status(f'Total connections: {self.connections_logged}', 'info')
        self.print_status(f'Unique IPs detected: {len(self.attacker_ips)}', 'info')

        if self.attacker_ips:
            self.print_status('Attack breakdown:', 'warning')
            for i, (ip, count) in enumerate(sorted(self.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10], 1):
                percentage = (count / self.connections_logged * 100) if self.connections_logged > 0 else 0
                self.print_status(f'  {i}. {ip:15} - {count} attempts ({percentage:.1f}%)', 'info')

        self.print_status('-' * 70, 'warning')

    def start(self) -> None:
        self.running = True
        start_time = datetime.now()
        executor: Optional[ThreadPoolExecutor] = None

        def signal_handler(sig, frame) -> None:
            if self.verbose:
                print()
            self.print_status('Honeypot shutting down...', 'warning')
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    server_socket.bind(('0.0.0.0', self.port))
                except OSError as e:
                    self.print_status(f'Error: Port {self.port} is already in use or requires root privileges: {e}', 'error')
                    logging.error(f'Failed to bind to port {self.port}: {e}')
                    sys.exit(1)

                server_socket.listen(self.max_connections)
                server_socket.settimeout(1.0)

                self.print_status(f'Honeypot active on port {self.port}...', 'success')
                self.print_status(f'Max concurrent connections: {self.max_connections}', 'info')
                self.print_status(f'Thread pool size: {self.max_workers}', 'info')
                self.print_status('Press Ctrl+C to exit', 'info')
                if self.verbose:
                    print()

                executor = ThreadPoolExecutor(max_workers=self.max_workers)

                while self.running:
                    try:
                        client_socket, client_address = server_socket.accept()
                        executor.submit(self.handle_connection, client_socket, client_address)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            self.print_status(f'Connection accept error: {e}', 'error')
                            logging.error(f'Connection accept error: {e}')

        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            self.print_status(f'Critical error: {e}', 'error')
            logging.critical(f'Critical error in main loop: {e}')
        finally:
            if executor:
                self.print_status('Shutting down thread pool...', 'info')
                executor.shutdown(wait=True)

            wait_time = 3
            self.print_status(f'Waiting {wait_time} seconds for threads to finish...', 'info')
            sleep(wait_time)

        runtime = datetime.now() - start_time
        hours, remainder = divmod(runtime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        runtime_str = f'{hours}h {minutes}m {seconds}s'

        logging.info(f'Honeypot stopped after {runtime_str} with {self.connections_logged} connections from {len(self.attacker_ips)} unique IPs')

        if self.attacker_ips:
            logging.info('--- Attack Summary ---')
            for ip, count in sorted(self.attacker_ips.items(), key=lambda x: x[1], reverse=True):
                logging.info(f'IP: {ip} - {count} attempts')

        self.print_status('Server socket closed.', 'success')
        self.print_summary(start_time, runtime_str)

def main() -> None:
    parser = argparse.ArgumentParser(description='SSH Honeypot - Simulate a vulnerable SSH server')
    subparsers = parser.add_subparsers(dest='command')

    run_parser = subparsers.add_parser('run', help='Start the honeypot')

    run_parser.add_argument('-p', '--port', type=int, default=Tunnelbreach.DEFAULT_PORT,
                          help=f'Port number (default: {Tunnelbreach.DEFAULT_PORT})')
    run_parser.add_argument('-s', '--stealth', action='store_true',
                          help='Run in stealth mode with minimal output')
    run_parser.add_argument('-w', '--workers', type=int, default=Tunnelbreach.MAX_THREAD_WORKERS,
                          help=f'Maximum number of worker threads (default: {Tunnelbreach.MAX_THREAD_WORKERS})')
    run_parser.add_argument('-c', '--connections', type=int, default=Tunnelbreach.MAX_CONNECTIONS,
                          help=f'Maximum number of concurrent connections (default: {Tunnelbreach.MAX_CONNECTIONS})')

    args = parser.parse_args()

    if args.command != 'run':
        parser.print_help()
        sys.exit(0)

    honeypot = Tunnelbreach(
        port=args.port,
        stealth_mode=args.stealth,
        max_workers=args.workers,
        max_connections=args.connections
    )

    honeypot.start()

if __name__ == '__main__':
    main()
