import uuid

import jwt

from foxden.config import settings


def main() -> None:
    print(jwt.encode({'jti': str(uuid.uuid4()), 'aud': 'login'}, settings.jwk))


if __name__ == '__main__':
    main()
