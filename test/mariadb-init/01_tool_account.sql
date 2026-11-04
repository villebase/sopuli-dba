-- The tier-1 MariaDB server's tool account, with exactly the grants of
-- docs/design/02-mariadb-privileges.md §2.1, and the ed25519 plugin, which a
-- new server does not load (sql/mariadb/02_client_hash_probe.py, CH4).
--
-- The image runs this once, as root, when it initialises an empty data
-- directory. The password is a test password, as root's is: the stack's
-- credentials are in the repository, and compose publishes the port on
-- loopback only (README.md). Unlike §2.1, it is set with IDENTIFIED BY, so the
-- server's logs may keep it. That is harmless for a password in the repository.

INSTALL SONAME 'auth_ed25519';

CREATE USER 'sopuli_admin'@'%' IDENTIFIED BY 'sopuli-test-admin';
GRANT CREATE USER ON *.* TO 'sopuli_admin'@'%';
GRANT SELECT (User, Host, plugin, password_expired, is_role,
              Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv,
              Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv,
              Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv,
              Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv,
              Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,
              Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv,
              Trigger_priv, Create_tablespace_priv, Delete_history_priv)
  ON mysql.user TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.roles_mapping TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.db            TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.tables_priv   TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.columns_priv  TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.procs_priv    TO 'sopuli_admin'@'%';
GRANT SELECT ON mysql.proxies_priv  TO 'sopuli_admin'@'%';
