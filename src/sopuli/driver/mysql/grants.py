"""The tool account's own grants on a MySQL server, as ``SHOW GRANTS`` prints
them. Tier 0.

``02-mysql-privileges.md`` §2.2 says what is read. Two reads, both open to any
account that can log in, with no grant of their own:

1. the roles granted straight to the tool account, from
   ``INFORMATION_SCHEMA.APPLICABLE_ROLES``. A mandatory role is listed there
   with the tool account as its grantee;
2. ``SHOW GRANTS FOR CURRENT_USER() USING`` each of them. ``USING`` expands a
   role whether or not it is active, and the roles granted to it in turn. The
   result is everything the tool account holds, or can hold after a
   ``SET ROLE``.

Measured on 8.0.46, 8.4.13 and 9.7.4 (``07_own_grants_probe.py``). ``SHOW
GRANTS`` with no ``USING`` expands only the active roles, and
``INFORMATION_SCHEMA.USER_PRIVILEGES`` lists only direct grants, so neither is
enough alone.

A line is parsed by its shape, not by a grammar of the whole statement. A line
this module cannot parse, such as the ``REVOKE`` that ``partial_revokes``
prints, is kept as text. A ``GRANT`` line kept this way that names
``SYSTEM_USER`` or ``ALL PRIVILEGES`` counts as holding ``SYSTEM_USER``
(:meth:`Grants.holds_system_user`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sopuli.driver.protocol import Cursor

#: The roles granted straight to the session's account: rows whose grantee is
#: the account itself, not a role it reaches.
DIRECT_ROLES = (
    "select ROLE_NAME, ROLE_HOST from information_schema.APPLICABLE_ROLES "
    "where GRANTEE = USER and GRANTEE_HOST = HOST order by ROLE_NAME, ROLE_HOST"
)

#: The account's grants with no role expanded beyond the active ones, for an
#: account that has no role.
OWN_GRANTS = "show grants"

#: The account's grants with every named role expanded. PyMySQL fills in each
#: ``%s`` as a quoted string, and ``'name'@'host'`` is how MySQL names a role.
GRANTS_USING = "show grants for current_user() using {roles}"

#: Every global privilege, ``ON *.*``.
GLOBAL = "*.*"

#: ``ALL PRIVILEGES ON *.*`` includes every dynamic privilege. ``SHOW GRANTS``
#: spells them out on 8.0.46, 8.4.13 and 9.7.4, so this is a second line.
ALL_PRIVILEGES = "ALL PRIVILEGES"

SYSTEM_USER = "SYSTEM_USER"


@dataclass(frozen=True)
class Privilege:
    """One privilege of a grant: ``CREATE USER``, or ``SELECT`` on columns."""

    name: str
    columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class Grant:
    """One line of ``SHOW GRANTS``.

    ``on`` is the object as printed, with the identifiers unquoted: ``*.*``,
    ``mysql.user``, ``acme%.*``. A role grant has no ``on``, and names the
    roles instead, as ``name@host``. A proxy grant's ``on`` is the account it
    proxies.
    """

    privileges: tuple[Privilege, ...] = ()
    on: str | None = None
    roles: tuple[str, ...] = ()
    grant_option: bool = False
    admin_option: bool = False

    def names(self) -> frozenset[str]:
        return frozenset(privilege.name for privilege in self.privileges)


@dataclass(frozen=True)
class Grants:
    """What the reads found: the grants parsed, and the lines that were not."""

    grants: tuple[Grant, ...]
    unparsed: tuple[str, ...] = ()

    def global_names(self) -> frozenset[str]:
        """Every privilege held ``ON *.*``."""
        found: set[str] = set()
        for grant in self.grants:
            if grant.on == GLOBAL:
                found |= grant.names()
        return frozenset(found)

    def holds_system_user(self) -> bool:
        """Whether ``SYSTEM_USER`` is held ``ON *.*``, or may be.

        A ``GRANT`` line this module cannot parse counts when it names
        ``SYSTEM_USER`` or ``ALL PRIVILEGES`` anywhere: the tool cannot tell
        where such a grant applies, so it refuses rather than guesses.
        """
        names = self.global_names()
        if SYSTEM_USER in names or ALL_PRIVILEGES in names:
            return True
        return any(
            line.upper().startswith("GRANT ")
            and (SYSTEM_USER in line.upper() or ALL_PRIVILEGES in " ".join(line.upper().split()))
            for line in self.unparsed
        )


def read(cursor: Cursor) -> Grants:
    """The two reads of the module docstring, parsed."""
    cursor.execute(DIRECT_ROLES)
    roles = [(str(name), str(host)) for name, host in cursor.fetchall()]
    if roles:
        placeholders = ", ".join("%s@%s" for _ in roles)
        cursor.execute(
            GRANTS_USING.format(roles=placeholders), [part for role in roles for part in role]
        )
    else:
        cursor.execute(OWN_GRANTS)
    return parse_all(str(row[0]) for row in cursor.fetchall())


def parse_all(lines: Iterable[str]) -> Grants:
    grants: list[Grant] = []
    unparsed: list[str] = []
    for line in lines:
        grant = parse(line)
        if grant is None:
            unparsed.append(line)
        else:
            grants.append(grant)
    return Grants(grants=tuple(grants), unparsed=tuple(unparsed))


def parse(line: str) -> Grant | None:
    """One ``GRANT`` line, or ``None`` for a line of another shape.

    The shapes, as 8.0.46, 8.4.13 and 9.7.4 print them::

        GRANT PROCESS, CREATE USER ON *.* TO `u`@`%` WITH GRANT OPTION
        GRANT BACKUP_ADMIN,SYSTEM_USER ON *.* TO `u`@`%`
        GRANT SELECT (`Host`, `User`) ON `mysql`.`user` TO `u`@`%`
        GRANT PROXY ON `other`@`%` TO `u`@`%`
        GRANT `r1`@`%`,`r2`@`%` TO `u`@`%` WITH ADMIN OPTION
    """
    if not line.upper().startswith("GRANT "):
        return None
    body = line[len("GRANT ") :].strip()
    to = _keyword(body, "TO")
    if to is None:
        return None
    head, tail = body[:to].strip(), body[to + len(" TO ") :].strip()
    tail_upper = tail.upper()
    grant_option = tail_upper.endswith(" WITH GRANT OPTION")
    admin_option = tail_upper.endswith(" WITH ADMIN OPTION")
    on = _keyword(head, "ON")
    if on is None:
        roles = tuple(_account(part) for part in top_level(head, ","))
        if not all(roles):
            return None
        return Grant(roles=roles, admin_option=admin_option)
    privileges = tuple(_privilege(part) for part in top_level(head[:on], ","))
    target = unquote(head[on + len(" ON ") :].strip())
    if not privileges or not target:
        return None
    return Grant(privileges=privileges, on=target, grant_option=grant_option)


def _keyword(text: str, word: str) -> int | None:
    """Where `` WORD `` first stands outside quotes and brackets, or ``None``."""
    needle = f" {word} "
    depth, quote = 0, ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "`'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text[index : index + len(needle)].upper() == needle:
            return index
    return None


def top_level(text: str, separator: str) -> list[str]:
    """``text`` split at ``separator`` outside quotes and brackets, each part
    stripped, empty parts dropped. A doubled quote inside a quoted name closes
    and reopens it, which leaves the split unchanged."""
    parts: list[str] = []
    depth, quote, start = 0, "", 0
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "`'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == separator:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def _privilege(text: str) -> Privilege:
    """``CREATE USER``, or ``SELECT (`Host`, `User`)``."""
    if "(" in text and text.endswith(")"):
        name, _, columns = text.partition("(")
        return Privilege(
            name=" ".join(name.split()).upper(),
            columns=tuple(unquote(column) for column in top_level(columns[:-1], ",")),
        )
    return Privilege(name=" ".join(text.split()).upper())


def _account(text: str) -> str:
    """```r1`@`%``` as ``r1@%``, or an empty string for anything else."""
    parts = top_level(text, "@")
    if len(parts) != 2:
        return ""
    return f"{unquote(parts[0])}@{unquote(parts[1])}"


def unquote(text: str) -> str:
    """Each quoted identifier in ``text`` without its quotes, and a doubled
    quote inside one as a single character. ```mysql`.`user``` is
    ``mysql.user``."""
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                if text[index + 1 : index + 2] == quote:
                    out.append(char)
                    index += 2
                    continue
                quote = ""
            else:
                out.append(char)
        elif char in "`'\"":
            quote = char
        else:
            out.append(char)
        index += 1
    return "".join(out).strip()
