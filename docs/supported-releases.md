# Tested releases

This page says which release of each database the tool has run on, and which it
has not. A release listed here is one somebody ran, not a promise of support. The README lists the databases. [measurements.md](measurements.md) has
each script, the release it ran on and what it showed, for the maintainers.

"Run end to end" means the commands ran against that release and changed real
passwords. "Probes ran" means the scripts in `sql/` measured what the release
does, which the tool's rules depend on. One release update is not every release
update. If you run the tool on a release that is not listed here, please report
what you find.

## Oracle

**What runs:** every command.

**Tested.** CI runs against the latest Oracle AI Database 26ai Free image. The
measurements were made on 23.26.2.0.0 and 23.26.3.0.0, and some on 23.26.3.3.0
on OCI. The maintainer also tests 21.3.0.0.0, 18.4.0.0.0 and 11.2.0.2.0 XE,
19.3.0.0.0 and 12.2.0.1.0 EE, and 19.32.0.0.0 on OCI.

**Not tested:** 12.1, 23ai releases before 23.26, and most 19c release updates.

## PostgreSQL

**What runs:** every command that connects to a database. What a cluster
lacks, such as a forced password change at next login, is refused before
anything changes.

**Tested.** The commands run end to end on 16.15. The probes in
`sql/postgres/` ran on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, and on
Supabase's 17.6.

**Not tested:** 12 and earlier, and the commands end to end on any release but
16.15. PostgreSQL on macOS and Linux arm64, where nobody has checked which
libpq the `postgres` extra installs.

## MySQL

**What runs:** every command that connects to a database.

**Tested.** The `creds` commands run end to end on 8.4.13. The probes in
`sql/mysql/` ran on 8.0.46, 8.4.13 and 9.7.4.

**Not tested:** releases before 8.0.46, and the `creds` commands end to end on
any release but 8.4.13.

## MariaDB

**What runs:** every command that connects to a database.

**Tested.** The `creds` commands run end to end on 11.8.9. The probes in
`sql/mariadb/` ran on 10.11.19, 11.4.13, 11.8.9 and 12.3.3. One probe also
wrote accounts on 10.4.34 and 10.6.28, and created its view on 10.6.28, before
upgrading them.

**Not tested:** releases before 10.11, except that one probe wrote accounts on
10.4.34 and 10.6.28 before upgrading them. The `creds` commands end to end on
any release but 11.8.9.

## SQL Server

**What runs:** every command that connects to a database, with `creds check`
on a Linux host only. What SQL Server has no counterpart for, such as
`account expire-password`, is refused before anything changes. Azure SQL
Database and Azure Synapse are refused when the tool connects.

**Tested.** The commands run end to end on 16.0.4325.4, on Linux. The probes in
`sql/mssql/` ran on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, and some on
16.0.1000.6 on Windows.

**Not tested:** releases before SQL Server 2019, SQL Server on Windows under a
domain's password policy, Azure SQL Managed Instance, and the commands end to
end on any release but 16.0.4325.4.
