<div id="nlogin-logo" align="center">
    <br />
    <img src="https://www.nickuc.com/static/assets/img/nlogin.svg" alt="nLogin Logo" width="500"/>
    <h3>Integrate nLogin with your website, forum and/or store.</h3>
</div>

## Usage:
1. [Instantiating the nLogin class](#instantiation)
2. [Verifying the Password](#verifying-the-password)
3. [Registering a Player](#registering-a-player)
4. [Changing the Password.](#changing-the-password)

### <div id="instantiation">Instantiation</div>

```php
require 'nLogin.php';

// Creates an instance
$nlogin = new nLogin("localhost", "root", "", "nlogin", false);
```

### <div id="verifying-the-password">Verifying the Password</div>

```php
require 'nLogin.php';

// Creates an instance
$nlogin = new nLogin("localhost", "root", "", "nlogin", false);

// Fetches the user identifier (search, mode)
$user_id = $nlogin->fetch_user_id("Player", nLogin::$FETCH_WITH_LAST_NAME);

// Verifies the password
$is_valid = $nlogin->verify_password($user_id, "password123");
```

### <div id="registering-a-player">Registering a Player</div>

```php
require 'nLogin.php';

// Creates an instance
$nlogin = new nLogin("localhost", "root", "", "nlogin", false);

// Fetches the user identifier (search, mode)
$user_id = $nlogin->fetch_user_id("Player", nLogin::$FETCH_WITH_LAST_NAME);

// Registers a player (username, plain password, e-mail, mojang id (optional), bedrock id (optional))
$success = $nlogin->register($user_id, "password123", 'youremail@domain.com', null, null);
```

### <div id="changing-the-password">Changing the Password</div>

```php
require 'nLogin.php';

// Creates an instance
$nlogin = new nLogin("localhost", "root", "", "nlogin", false);

// Fetches the user identifier (search, mode)
$user_id = $nlogin->fetch_user_id("Player", nLogin::$FETCH_WITH_LAST_NAME);

// Changes the password (user identifier, new plain password)
$success = $nlogin->change_password($user_id, "newpassword123");
```

## <div id="license">License</div>
This code or part of it was taken from the AuthMe project, licensed under the GNU General Public License v3.0 (https://github.com/AuthMe/AuthMeReloaded/blob/master/LICENSE)<br>
<br>
For more details, access the original source code: <br>
https://github.com/AuthMe/AuthMeReloaded/tree/master/samples/website_integration

## <div id="nodejs">Node.js</div>

If you use Node.js, take a look at the work done by tiagodinis33: https://gitlab.com/tiagodinis33/nlogin-js
