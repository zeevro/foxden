from foxden.server import app, simple, upload  # noqa: F401


try:
    import jwt
    import foxden.server.oidc
except ImportError:
    pass


__all__ = ['app']
