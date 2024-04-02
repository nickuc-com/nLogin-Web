<!--
  This code or part of it was taken from the AuthMe project,
  licensed under the GNU General Public License v3.0 (https://github.com/AuthMe/AuthMeReloaded/blob/master/LICENSE)
 
  For more details, access the original source code:
  https://github.com/AuthMe/AuthMeReloaded/tree/master/samples/website_integration 
-->

<!--
  This is a demo page for nLogin website integration.
  See nLogin.php for the PHP code you need.
-->
<!DOCTYPE html>
<html lang="en">
 <head>
   <title>nLogin Integration Sample</title>
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
 </head>
 <body>

<?php
ini_set('display_errors', 'On');
error_reporting(E_ALL);

require 'nLogin.php';

// Enter your database information and if you are using "username-appender" option bellow
$nlogin = new nLogin('localhost', 'root', '', 'nlogin', false);

$action = get_from_post_or_empty('action');
$user = get_from_post_or_empty('username');
$pass = get_from_post_or_empty('password');
$email = get_from_post_or_empty('email');

$was_successful = false;
if ($action && $user && $pass) {
  switch ($action) {
    case 'Log In':
      $was_successful = process_login($user, $pass, $nlogin);
      break;

    case 'Register':
      $was_successful = process_register($user, $pass, $email, $nlogin);
      break;
  }
}

if (!$was_successful) {
  echo '<h1>Login sample</h1>

  This is a demo form for nLogin website integration. Enter your nLogin login details
  into the following form to test it.

  <form method="post">
    <table>
      <tr><td>Name</td><td><input type="text" value="' . htmlspecialchars($user) . '" name="username" /></td></tr>
      <tr><td>Email</td><td><input type="text" value="' . htmlspecialchars($email) . '" name="email" /></td></tr>
      <tr><td>Pass</td><td><input type="password" value="' . htmlspecialchars($pass) . '" name="password" /></td></tr>
      <tr>
        <td><input type="submit" name="action" value="Log In" /></td>
        <td><input type="submit" name="action" value="Register" /></td>
      </tr>
    </table>
  </form>';
}

function get_from_post_or_empty($index_name) {
  return trim(
    filter_input(INPUT_POST, $index_name, FILTER_UNSAFE_RAW, FILTER_REQUIRE_SCALAR | FILTER_FLAG_STRIP_LOW) 
      ?: '');
}


// Login logic
function process_login($user, $pass, nLogin $nlogin) {
  $user_id = $this->fetch_user_id($user, nLogin::$FETCH_WITH_LAST_NAME);
  if ($user_id == null) {
    echo '<h1>Error</h1>Unfortunately, there was an error while fetching the user id.';
  } else if ($nlogin->verify_password($user_id, $pass)) {
    printf('<h1>Hello, %s!</h1>', htmlspecialchars($user));
    echo 'Successful login. Nice to have you back!'
      . '<br /><a href="index.php">Back to form</a>';
    return true;
  } else {
    echo '<h1>Error</h1> Invalid username or password.';
  }
  return false;
}

// Register logic
function process_register($user, $pass, $email, nLogin $nlogin) {
  $user_id = $this->fetch_user_id($user, nLogin::$FETCH_WITH_LAST_NAME);
  if ($user_id == null) {
    echo '<h1>Error</h1>Unfortunately, there was an error while fetching the user id.';
  } else if ($user_id != -1) {
    echo '<h1>Error</h1> This user already exists.';
  } else if (!is_email_valid($email)) {
    echo '<h1>Error</h1> The supplied email is invalid.';
  } else {
    // Note that we don't validate the password or username at all in this demo...
    $register_success = $nlogin->register($user, $pass, $email);
    if ($register_success) {
      printf('<h1>Welcome, %s!</h1>Thanks for registering', htmlspecialchars($user));
      echo '<br /><a href="index.php">Back to form</a>';
      return true;
    } else {
      echo '<h1>Error</h1>Unfortunately, there was an error during the registration.';
    }
  }
  return false;
}

function is_email_valid($email) {
  return trim($email) === ''
    ? true // accept no email
    : filter_var($email, FILTER_VALIDATE_EMAIL);
}
?>

  </body>
</html>
