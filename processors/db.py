import sqlite3
from typing import Dict, Any, List
from pathlib import Path

class DB:
    @staticmethod
    def init_nmap_db(db_path: Path, table_name: str) -> None:
        """
        Initialize the SQLite database and create the table if it does not exist.
        """
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                service TEXT,
                version TEXT,
                UNIQUE(ip, port, protocol)
            );
        """)
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_ip ON {table_name}(ip)")
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_port ON {table_name}(port)")
        conn.commit()
        conn.close()

    @staticmethod
    def insert_nmap_scan_results(db_path: Path, json_object: Dict[str, List[Dict[str, Any]]], table_name: str) -> None:
        """
        Insert scan results into the SQLite database.

        :param db_path: Path to the SQLite database file.
        :param results: Dict mapping IP -> list of port/service objects, e.g.:

            {
              "192.168.5.199": [
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "1.0"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": None}
              ],
              "192.168.5.200": [...]
            }
        """
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        insert_sql = f"""
            INSERT OR IGNORE INTO {table_name} (ip, port, protocol, service, version)
            VALUES (?, ?, ?, ?, ?)
        """

        rows = []
        for ip, ports in json_object.items():
            for p in ports:
                port_val = p.get("port")
                if port_val is None:
                    continue  # skip entries without a port
                try:
                    port_int = int(port_val)
                except (ValueError, TypeError):
                    continue  # skip if the port is not convertible
                rows.append((
                    ip,
                    port_int,
                    p.get("protocol"),
                    p.get("service"),
                    p.get("version"),
                ))

        cur.executemany(insert_sql, rows)
        conn.commit()
        conn.close()




# def main():

#     try:

#         # First, initialize DB (do this once)
#         init_db("scan_results.db")

#         # Sample JSON object from your parser
#         sample_results = {
#             "192.168.5.199": [
#                 {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": None},
#                 {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": None},
#                 {"port": 49154, "protocol": "tcp", "service": None, "version": None}
#             ],
#             "192.168.5.200": [
#                 {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.4"}
#             ]
#         }

#         # Insert into database
#         insert_scan_results("scan_results.db", sample_results)

#     except Exception as e:
#         print(e)

# if __name__ == "__main__":
#     main()