#!/usr/bin/env python3
"""Convert an SSH known_hosts file into a WebSSH YAML config.

Usage:
    python scripts/known_hosts_to_yaml.py [known_hosts_file]

Defaults to ~/.ssh/known_hosts if no file is specified.
Output is written to stdout.
"""

import re
import sys
import os
from collections import defaultdict

VALID_KEY_TYPES = {
    'ssh-rsa', 'ssh-ed25519',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
}

# Match bracketed [host]:port format
BRACKETED_RE = re.compile(r'^\[(.+)\]:(\d+)$')


def parse_host_entry(host_str):
    """Parse a host string into (hostname, port) tuples.

    Handles formats like:
        hostname
        [hostname]:port
        hostname,hostname2
        [hostname]:port,[hostname2]:port
    """
    results = []
    for part in host_str.split(','):
        part = part.strip()
        if not part:
            continue
        m = BRACKETED_RE.match(part)
        if m:
            results.append((m.group(1), int(m.group(2))))
        else:
            results.append((part, 22))
    return results


def parse_known_hosts(filepath):
    """Parse a known_hosts file and return a dict of (hostname, port) -> [keys]."""
    hosts = defaultdict(list)
    hashed_count = 0

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Count hashed entries (start with |) — can't reverse these
            if line.startswith('|'):
                hashed_count += 1
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            host_str = parts[0]
            key_type = parts[1]
            key_data = parts[2]

            if key_type not in VALID_KEY_TYPES:
                continue

            key_str = '{} {}'.format(key_type, key_data)

            for hostname, port in parse_host_entry(host_str):
                hosts[(hostname, port)].append(key_str)

    if hashed_count:
        print(
            'Note: Skipped {} hashed entries. Hashed hostnames cannot be '
            'reversed.\nUse ssh-keyscan to get keys for specific hosts, e.g.:'
            '\n  ssh-keyscan -t ed25519,rsa hostname\n'.format(hashed_count),
            file=sys.stderr
        )

    return hosts


def generate_yaml(hosts):
    """Generate YAML config from parsed hosts."""
    lines = [
        '# WebSSH Configuration',
        '# Generated from known_hosts',
        '',
        'hosts:',
    ]

    for (hostname, port), keys in sorted(hosts.items()):
        lines.append('  - hostname: "{}"'.format(hostname))
        if port != 22:
            lines.append('    port: {}'.format(port))
        if len(keys) == 1:
            lines.append('    host_key: "{}"'.format(keys[0]))
        elif len(keys) > 1:
            lines.append('    host_key:')
            for key in keys:
                lines.append('      - "{}"'.format(key))

    lines.append('')
    return '\n'.join(lines)


def main():
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = os.path.expanduser('~/.ssh/known_hosts')

    if not os.path.isfile(filepath):
        print('Error: {} not found'.format(filepath), file=sys.stderr)
        sys.exit(1)

    hosts = parse_known_hosts(filepath)
    if not hosts:
        print('No hosts found in {}'.format(filepath), file=sys.stderr)
        sys.exit(1)

    print(generate_yaml(hosts))


if __name__ == '__main__':
    main()
