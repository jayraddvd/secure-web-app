import sqlite3

def create_database():

    connection = sqlite3.connect("users.db")

    cursor = connection.cursor()

    cursor.execute("""

        CREATE TABLE IF NOT EXISTS users(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL

        )

    """)

    connection.commit()

    connection.close()

    print("Database create sucessfully!")

create_database()