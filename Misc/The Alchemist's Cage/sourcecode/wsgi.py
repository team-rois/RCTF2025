"""WSGI entrypoint for production servers like Gunicorn."""

from app import app

__all__ = ("app",)
