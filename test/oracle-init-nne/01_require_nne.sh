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
# on each new connection, so nothing has to restart. The service's healthcheck
# looks for the begin marker, so a start where this fails stays unhealthy.
#
# The image may source this file instead of running it, so it sets no shell
# options and does not exit.

nne_target="${ORACLE_BASE_HOME:-}/network/admin/sqlnet.ora"
nne_source=/container-entrypoint-startdb.d/sqlnet-nne.ora
nne_begin="# BEGIN sopuli oracle-init-nne"
nne_end="# END sopuli oracle-init-nne"

if [ -z "${ORACLE_BASE_HOME:-}" ] || [ ! -s "${nne_target}" ] || [ ! -s "${nne_source}" ]; then
  echo "ERROR: sqlnet-nne.ora not added: ${nne_target} or ${nne_source} is missing or empty"
# Remove the block an earlier start added, keep the image's own lines, and add
# the current block.
elif sed "/^${nne_begin}\$/,/^${nne_end}\$/d" "${nne_target}" > /tmp/sqlnet.ora.sopuli \
  && [ -s /tmp/sqlnet.ora.sopuli ] \
  && {
    cat /tmp/sqlnet.ora.sopuli
    echo "${nne_begin}"
    cat "${nne_source}"
    echo "${nne_end}"
  } > /tmp/sqlnet.ora.sopuli.new \
  && cat /tmp/sqlnet.ora.sopuli.new > "${nne_target}"; then
  echo "sqlnet-nne.ora added to ${nne_target}"
else
  echo "ERROR: sqlnet-nne.ora not added to ${nne_target}"
fi
rm -f /tmp/sqlnet.ora.sopuli /tmp/sqlnet.ora.sopuli.new
