import sqlite3

class Database:
    def __init__(self, db_name):
        self.db_name = db_name

    def create_tables(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS scans
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             ip_address TEXT,
             port_number TEXT,
             report TEXT,
             scan_time TEXT,
             user_id INTEGER,
             FOREIGN KEY (user_id) REFERENCES users(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT UNIQUE,
             password TEXT)''')

        conn.commit()
        conn.close()

    def add_user(self, username, password):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))

        conn.commit()
        conn.close()

    def get_user(self, username):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()

        conn.commit()
        conn.close()

        return user

    def add_scan(self, ip_address, port_number, report, scan_time, user_id):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('INSERT INTO scans (ip_address, port_number, report, scan_time, user_id) VALUES (?, ?, ?, ?, ?)',
                  (ip_address, port_number, report, scan_time, user_id))

        conn.commit()
        conn.close()

    def get_scans_by_user(self, user_id):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('SELECT * FROM scans WHERE user_id=?', (user_id,))
        scans = c.fetchall()

        conn.commit()
        conn.close()

        return scans
