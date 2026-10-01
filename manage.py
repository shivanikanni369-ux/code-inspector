#!/usr/bin/env python
"""Django's command-line utility."""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    # manage.py is for local work, so debug mode is on unless you say otherwise.
    # Production servers start through config/wsgi.py, which defaults to debug OFF.
    os.environ.setdefault("DJANGO_DEBUG", "1")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Did you activate your virtual environment "
            "and run 'pip install -r requirements.txt'?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
