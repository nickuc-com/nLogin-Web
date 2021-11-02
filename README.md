# nLogin-Web
This code or part of it was taken from the AuthMe project, licensed under the GNU General Public License v3.0 (https://github.com/AuthMe/AuthMeReloaded/blob/master/LICENSE)<br>
<br>
For more details, access the original source code: <br>
https://github.com/AuthMe/AuthMeReloaded/tree/master/samples/website_integration

## How to use?
1. [Instantiating and connecting to the database](#connection)
2. [Checking the password.](#login)
3. [Registering an account.](#register)
4. [Changing the password.](#changePassword)

### <div id="connection">Connection.</div>

```php
require 'nLogin.php';

// host, user, password, database
$nlogin = new nLogin("localhost", "root", "", "nlogin");
```

### <div id="login">Login.</div>

```php
require 'nLogin.php';

// host, user, password, database
$nlogin = new nLogin("localhost", "root", "", "nlogin");

// username, plain password
$nlogin->checkPassword("zlDeath", "mypassword");
```

### <div id="register">Register.</div>

```php
require 'nLogin.php';

// host, user, password, database
$nlogin = new nLogin("localhost", "root", "", "nlogin");

// username, plain password, e-mail
$nlogin->register("zlDeath", "mypassword", 'youremail@domain.com');
```

### <div id="changePassword">Changepassword.</div>

```php
require 'nLogin.php';

// host, user, password, database
$nlogin = new nLogin("localhost", "root", "", "nlogin");

// username, plain password
$nlogin->changePassword("zlDeath", "newpassword");
```

## <div id="nodejs">Node.js</div>

If you use Node.js, take a look at the work done by tiagodinis33: https://gitlab.com/tiagodinis33/nlogin-js
