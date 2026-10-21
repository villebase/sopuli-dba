#!/bin/bash
# Adds sqlnet-nne.ora to the server's sqlnet.ora on each start of oracle-nne.
#
# compose.yaml cannot mount the file at its final place. That place is under
# oradata/dbconfig/FREE, and the image's entrypoint takes an existing
# dbconfig/FREE directory to mean a database exists. It then skips creating one
# and the container exits with ORA-01078.
#
# This runs from /container-entrypoint-startdb.d, after the database is created,
# on the first start and on every later one. A dedicated server reads sqlnet.ora
# on each new connection, so nothing has to restart.
#
# The image may source this file instead of running it, so it sets no shell
# options and does not exit.

nne_target="${ORACLE_BASE_HOME}/network/admin/sqlnet.ora"
nne_begin="# BEGIN sopuli oracle-init-nne"
nne_end="# END sopuli oracle-init-nne"

# Remove the block an earlier start added, keep the image's own lines, and add
# the current block.
sed "/^${nne_begin}\$/,/^${nne_end}\$/d" "${nne_target}" > /tmp/sqlnet.ora.sopuli
{
  cat /tmp/sqlnet.ora.sopuli
  echo "${nne_begin}"
  cat /container-entrypoint-startdb.d/sqlnet-nne.ora
  echo "${nne_end}"
} > "${nne_target}"
rm -f /tmp/sqlnet.ora.sopuli
echo "sqlnet-nne.ora added to ${nne_target}"
