#!/usr/bin/env python3
""" Encrypting passwords with bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """Converts to unicode Returns salted, hashes password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if hashed and unhashed passwords are formed from given password
    Returns bool
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
