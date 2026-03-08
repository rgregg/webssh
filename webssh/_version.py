import subprocess

# Fallback version used when git is not available (e.g. in Docker images).
# Updated at build time via Dockerfile ARG or manually for releases.
FALLBACK_VERSION = '1.7.0'


def _get_version():
    try:
        out = subprocess.check_output(
            ['git', 'describe', '--tags', '--always'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        # Strip leading 'v' if present (v1.7.0 -> 1.7.0)
        if out.startswith('v'):
            out = out[1:]
        return out
    except Exception:
        return FALLBACK_VERSION


def _parse_version_info(version):
    # Extract major.minor.patch from version like "1.7.0" or "1.7.0-3-gabcdef"
    base = version.split('-')[0]
    parts = base.split('.')
    try:
        return tuple(int(p) for p in parts[:3])
    except (ValueError, IndexError):
        return (0, 0, 0)


__version__ = _get_version()
__version_info__ = _parse_version_info(__version__)
