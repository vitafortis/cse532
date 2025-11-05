# migrate_db.py
from sqlalchemy import text
from app import app, db
from app.models import PackageStat

with app.app_context():
    engine = db.engine
    connection = engine.connect()

    # Query table info safely using exec_driver_sql()
    result = connection.exec_driver_sql("PRAGMA table_info(package_stat);")
    columns = [row[1] for row in result]
    print("Current columns:", columns)

    if "total_vulns_recorded" not in columns:
        print("Adding column 'total_vulns_recorded' to package_stat...")
        connection.exec_driver_sql(
            "ALTER TABLE package_stat ADD COLUMN total_vulns_recorded INTEGER DEFAULT 0;"
        )
        print("Column added successfully!")
    else:
        print("Column 'total_vulns_recorded' already exists, skipping.")

    connection.close()
    print("Migration complete.")
