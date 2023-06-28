import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('urls.db')
c = conn.cursor()

# Check if the 'urls' table exists
c.execute("PRAGMA table_info(urls)")
existing_columns = [column[1] for column in c.fetchall()]

# Add the missing columns if they are not already present
if 'page_title' not in existing_columns:
    c.execute("ALTER TABLE urls ADD COLUMN page_title TEXT")
    print("Added 'page_title' column.")
if 'has_form' not in existing_columns:
    c.execute("ALTER TABLE urls ADD COLUMN has_form INTEGER")
    print("Added 'has_form' column.")

# Commit the changes and close the connection
conn.commit()
conn.close()
