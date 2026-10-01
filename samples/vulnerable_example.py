"""Deliberately insecure demo file. Every credential below is fake.
Scan this file with the tool to see what a report looks like. Never copy these patterns."""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys

DEBUG = True
ALLOWED_HOSTS = ["*"]
DB_PASSWORD = "hunter2-not-a-real-password"
API_KEY = "sk-demo-1234567890abcdef"


def find_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()


def find_user_by_id(conn, user_id):
    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall()


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True)


def calculate(expression):
    return eval(expression)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_session(blob):
    try:
        return pickle.loads(blob)
    except:
        pass


def add_item(item, items=[]):
    items.append(item)
    return items
