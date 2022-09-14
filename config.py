from os import getenv

JWT_SECRET_KEY = getenv(
    "JWT_SECRET_KEY",
    None,
)
USERNAME = getenv(
    "USERNAME",
    None,
)
PASSWORD = getenv(
    "PASSWORD",
    None,
)
JWT_EXPIRES_IN_MINUTES = int(
    getenv(
        "JWT_EXPIRES_IN_MINUTES",
        30,
    ),
)
