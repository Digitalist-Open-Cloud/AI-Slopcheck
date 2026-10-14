from src.db import Database


def get_user(user_id):
    # TODO: add caching
    return Database().fetch(user_id)
