# from cassandra.cluster import Cluster
# from cassandra.cluster import NoHostAvailable
# from werkzeug.security import generate_password_hash

# # Connect to Cassandra
# cluster = Cluster(["192.168.1.10 ", "192.168.1.11" , "192.168.1.12"])
# session = cluster.connect()

# # Create keyspace if it does not exist
# session.execute("""
#     CREATE KEYSPACE IF NOT EXISTS user_data 
#     WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
# """)

# # Switch to the keyspace
# session.set_keyspace("user_data")

# # Create users table if it does not exist
# session.execute("""
#     CREATE TABLE IF NOT EXISTS users (
#         username TEXT PRIMARY KEY,
#         password_hash TEXT,
#         created_at TIMESTAMP
#     );
# """)

# # Create chats table to store metadata about each chat session
# session.execute("""
#     CREATE TABLE IF NOT EXISTS chats (
#         chat_id UUID PRIMARY KEY,
#         user_id TEXT,
#         created_at TIMESTAMP,
#         title TEXT  

#     );
# """)

# # Create messages table to store individual messages within each chat session
# session.execute("""
#     CREATE TABLE IF NOT EXISTS messages (
#         chat_id UUID,
#         message_id UUID,
#         text TEXT,
#         timestamp TIMESTAMP,
#         PRIMARY KEY (chat_id , message_id)
#     );
# """)

# print("Keyspace and tables are ready.")

# # Insert an admin user if not exists
# admin_password_hash = generate_password_hash("admin")
# session.execute("""
#     INSERT INTO users (username, password_hash, created_at)
#     VALUES (%s, %s, toTimestamp(now()))
# """, ("admin", admin_password_hash))

# print("Admin user created successfully.")
