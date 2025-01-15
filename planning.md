# Planning

## Features

- Multiple index backend options

  - Dummy (for testing)
  - SQL database
    - SQLite
    - PostgreSQL
    - Multiple file storage options
      - Blobs in DB
      - Separate storage backend
  - Static files
    - PEP-503 only
    - PEP-691 only
    - PEP-503 and PEP-691 with server-driven content negotiation
      - Provide example nginx configuration

- Multiple file storage backend options
  - File-system
  - AWS S3
  - Git?

- PyPI-compatible Simple Repository API

- PyPI-compatible `upload` endpoint
  - PyPI-compatible *"truested publishing"*
    - GitHub Actions
  - Tested against clients
    - `twine`
    - `uv`
  - Can be serverless
    - AWS EC2 Lambda

- 100% Unit-test coverage

- Distribution "yanking" (PEP-592)

## PyPI API compatibility PEPs
- API version 1.0: PEP-503, PEP-592, PEP-629, PEP-658, PEP-691, PEP-714
- API version 1.1: PEP-700
- API version 1.2: PEP-708
- API version 1.3: PEP-740

## MVP
- Index backend options
  - Dummy
  - Static files
    - PEP-503 only

- File storage backend
  - File-system
  - AWS S3

- Simple Repository API version 1.0: PEP-503, PEP-629, PEP-658, PEP-691, PEP-714
