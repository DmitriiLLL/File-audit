#!/usr/bin/env python3
"""
Simple File Audit System
Features:
 - Configurable via INI file
 - Role-based permissions
 - Audit logging of operations
 - CLI interface for file operations and audit reporting
"""
import os
import shutil
import logging
import argparse
import configparser
import datetime
from functools import wraps

# ---------------------------------------
# Configuration
# ---------------------------------------
CONFIG_FILE = 'audit_config.ini'
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

LOG_FILE = config.get('audit', 'log_file', fallback='audit.log')
LOG_LEVEL = config.get('audit', 'log_level', fallback='INFO').upper()

logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# ---------------------------------------
# Role Permissions
# ---------------------------------------
ROLE_PERMISSIONS = {
    'admin':   ['read', 'write', 'delete', 'move', 'copy', 'metadata', 'report'],
    'user':    ['read', 'write', 'metadata'],
    'auditor': ['read', 'metadata', 'report'],
    'guest':   ['read']
}

# ---------------------------------------
# Audit Decorator
# ---------------------------------------
def requires_permission(op):
    def decorator(fn):
        @wraps(fn)
        def wrapper(self, filename, *args, **kwargs):
            if op not in ROLE_PERMISSIONS.get(self.role, []):
                self._log_event(op, filename, 'FAILURE', 'Permission denied')
                return f"Operation '{op}' denied for role '{self.role}'"
            try:
                result = fn(self, filename, *args, **kwargs)
                self._log_event(op, filename, 'SUCCESS')
                return result
            except Exception as e:
                self._log_event(op, filename, 'ERROR', str(e))
                return f"Error on '{op}': {e}"
        return wrapper
    return decorator

# ---------------------------------------
# AuditSystem Class
# ---------------------------------------
class AuditSystem:
    def __init__(self, user, role):
        self.user = user
        self.role = role

    def _log_event(self, operation, filename, status, info=''):
        timestamp = datetime.datetime.now().isoformat()
        msg = f"USER={self.user} | OP={operation} | FILE={filename} | STATUS={status}"
        if info:
            msg += f" | INFO={info}"
        logging.info(msg)

    @requires_permission('read')
    def read(self, filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()

    @requires_permission('write')
    def write(self, filename, data):
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(data + '\n')
        return 'Write successful.'

    @requires_permission('delete')
    def delete(self, filename):
        os.remove(filename)
        return 'Delete successful.'

    @requires_permission('copy')
    def copy(self, filename, dest):
        shutil.copy2(filename, dest)
        return f'Copied to {dest}'

    @requires_permission('move')
    def move(self, filename, dest):
        shutil.move(filename, dest)
        return f'Moved to {dest}'

    @requires_permission('metadata')
    def metadata(self, filename):
        stats = os.stat(filename)
        return {
            'size': stats.st_size,
            'created': datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
            'modified': datetime.datetime.fromtimestamp(stats.st_mtime).isoformat()
        }

    @requires_permission('report')
    def report(self, since=None):
        lines = []
        with open(LOG_FILE, 'r', encoding='utf-8') as lf:
            for line in lf:
                if not since or since in line:
                    lines.append(line.strip())
        return '\n'.join(lines)

# ---------------------------------------
# CLI Interface
# ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description='File Audit System')
    parser.add_argument('user', help='User name')
    parser.add_argument('role', help='Role name')
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_read = subparsers.add_parser('read')
    parser_read.add_argument('filename')

    parser_write = subparsers.add_parser('write')
    parser_write.add_argument('filename')
    parser_write.add_argument('data')

    parser_delete = subparsers.add_parser('delete')
    parser_delete.add_argument('filename')

    parser_copy = subparsers.add_parser('copy')
    parser_copy.add_argument('filename')
    parser_copy.add_argument('dest')

    parser_move = subparsers.add_parser('move')
    parser_move.add_argument('filename')
    parser_move.add_argument('dest')

    parser_meta = subparsers.add_parser('metadata')
    parser_meta.add_argument('filename')

    parser_report = subparsers.add_parser('report')
    parser_report.add_argument('--since', help='Filter start timestamp', default=None)

    args = parser.parse_args()
    audit = AuditSystem(args.user, args.role)

    if args.command == 'read':
        print(audit.read(args.filename))
    elif args.command == 'write':
        print(audit.write(args.filename, args.data))
    elif args.command == 'delete':
        print(audit.delete(args.filename))
    elif args.command == 'copy':
        print(audit.copy(args.filename, args.dest))
    elif args.command == 'move':
        print(audit.move(args.filename, args.dest))
    elif args.command == 'metadata':
        print(audit.metadata(args.filename))
    elif args.command == 'report':
        print(audit.report(args.since))

if __name__ == '__main__':
    main()
