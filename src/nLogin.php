<?php
/*
 * This code or part of it was taken from the AuthMe project,
 * licensed under the GNU General Public License v3.0 (https://github.com/AuthMe/AuthMeReloaded/blob/master/LICENSE)
 * 
 * For more details, access the original source code:
 * https://github.com/AuthMe/AuthMeReloaded/tree/master/samples/website_integration 
 */

/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

require 'Algorithms/Algorithm.php';
require 'Algorithms/Bcrypt.php';
require 'Algorithms/Sha256.php';
require 'Algorithms/AuthMe.php';

class nLogin
{

	const TABLE_NAME = 'nlogin';

	private $BCRYPT;
	private $SHA256;
	private $AUTHME;
	private $DEF_ALGO;

	private $db_host, $db_user, $db_pass, $db_name;

	/**
	 * Constructor responsible for creating the connection with the database
	 *
	 * @param string $db_host MySQL Host
	 * @param string $db_user MySQL User
	 * @param string $db_pass MySQL Password
	 * @param string $db_name MySQL Database Name 
	 */
	public function __construct($db_host, $db_user, $db_pass, $db_name)
	{
		$this->BCRYPT = new Bcrypt();
		$this->SHA256 = new Sha256();
		$this->AUTHME = new AuthMe();
		$this->DEF_ALGO = $this->BCRYPT;

		$this->db_host = $db_host;
		$this->db_user = $db_user;
		$this->db_pass = $db_pass;
		$this->db_name = $db_name;
	}

	/**
	 * Destroys the class instance
	 */
	public function __destruct()
	{
		$this->connection = null;
	}

	/**
	 * Entry point function to check supplied credentials against the nLogin database.
	 *
	 * @param string $username the username
	 * @param string $password the password
	 * @return bool true if the data is correct, false otherwise
	 */
	public function checkPassword($username, $password) {
		if (is_scalar($username) && is_scalar($password)) {
			$hash = $this->getHashedPassword($username);
			if ($hash) {
				$algorithm = $this->detectAlgorithm($hash);
				if ($algorithm) {
					return $algorithm->isValidPassword($password, $hash);
				}
			}
		}
		return false;
	}

	/**
	 * Returns whether the user exists in the database or not.
	 *
	 * @param string $username the username to check
	 * @return bool true if the user exists; false otherwise
	 */
	public function isUserRegistered($username) {
		$mysqli = $this->getMySqli();
		if ($mysqli !== null) {
			$username = trim($username);
			$stmt = $mysqli->prepare('SELECT 1 FROM ' . self::TABLE_NAME . ' WHERE name = ? LIMIT 1');
			$stmt->bind_param('s', $username);
			$stmt->execute();
			return $stmt->fetch();
		}

		return true;
	}

	/**
	 * Returns whether the address exists in the database or not.
	 *
	 * @param string $address the username to check
	 * @return bool true if the address exists; false otherwise
	 */
	public function isIpRegistered($address)
	{
		$mysqli = $this->getMySqli();
		if ($mysqli !== null) {
			$stmt = $mysqli->prepare('SELECT 1 FROM ' . self::TABLE_NAME . ' WHERE address = ? LIMIT 1');
			$stmt->bind_param('s', $address);
			$stmt->execute();
			return $stmt->fetch();
		}

		return true;
	}

	/**
	 * Registers a player with the given username.
	 *
	 * @param string $username the username to register
	 * @param string $password the password to associate to the user
	 * @param string $email the email (may be empty)
	 * @param string $address the address (optional)
	 * @return bool whether or not the registration was successful
	 */
	public function register($username, $password, $email, $address = null) {
		if ($address == null) {
			$address = $_SERVER['REMOTE_ADDR'];
		}
		$mysqli = $this->getMySqli();
		if ($mysqli !== null) {
			$username = trim($username);
			$email = $email ? $email : '';
			$hash = $this->hash($password);
			$username_lower = strtolower($username);
			if ($this->isUserRegistered($username)) {
				$stmt = $mysqli->prepare('UPDATE ' . self::TABLE_NAME . ' SET ' 
					. 'password = ?, address = ?, email = ? WHERE name = ?');
				$stmt->bind_param('ssss', $hash, $address, $email, $username_lower);
			}
			else
			{
				$stmt = $mysqli->prepare('INSERT INTO ' . self::TABLE_NAME . ' (name, realname, password, address, email) '
					. 'VALUES (?, ?, ?, ?, ?) ');
				$stmt->bind_param('sssss', $username_lower, $username, $hash, $address, $email);
			}
			return $stmt->execute();
		}
		return false;
	}

	/**
	 * Changes password for player.
	 *
	 * @param string $username the username
	 * @param string $password the password
	 * @return bool true whether or not password change was successful 
	 */
	public function changePassword($username, $password) {
		$mysqli = $this->getMySqli();
		if ($mysqli !== null) {
			$username = trim($username);
			$hash = $this->hash($password);
			$stmt = $mysqli->prepare('UPDATE ' . self::TABLE_NAME . ' SET password = ? WHERE name = ?');
			$username_lower = strtolower($username);
			$stmt->bind_param('ss', $hash, $username_lower);
			return $stmt->execute();
		}
		return false;
	}

	/**
	 * Retorna o algoritmo usado na senha.
	 *
	 * @param string $hashed_pass Senha criptografada.
	 * @return object Retorna o algoritmo usado. Se for desconhecido ou não suportado, retorna null.
	 */
	private function detectAlgorithm($hashed_pass)
	{
		$algo = strtoupper(strpos($hashed_pass, '$') !== false ? explode('$', $hashed_pass)[1] : '');
		switch ($algo) {
		 	case '2':
		 	case '2A':
		 		return $this->BCRYPT;

		 	case "PBKDF2":
				// will be added
				return null;
			
			case "ARGON2I":
				// will be added
				return null;
			
			case "SHA256":
			   return $this->SHA256;
		 	
			default:		
		 		$needle = '$AUTHME';
				$length = strlen($needle);
				if ($length && substr($hashed_pass, -$length) === $needle) {
					return $this->AUTHME;
				}
		 		return null;
		 } 
	}

	/**
	 * Hashes the given password.
	 *
	 * @param $password string the clear-text password to hash
	 * @return string the resulting hash
	 */
	private function hash($password) {
		return $this->DEF_ALGO->hash($password);
	}

	/**
	 * Returns a connection to the database.
	 *
	 * @return mysqli|null the mysqli object or null upon error
	 */
	private function getMySqli() {
		$mysqli = new mysqli($this->db_host, $this->db_user, $this->db_pass, $this->db_name);
		if (mysqli_connect_error()) {
			printf('Could not connect to ' . $this->db_name . ' database. Errno: %d, error: "%s"',
				mysqli_connect_errno(), mysqli_connect_error());
			return null;
		}
		return $mysqli;
	}

	/**
	 * Retrieves the hash associated with the given user from the database.
	 *
	 * @param string $username the username whose hash should be retrieved
	 * @return string|null the hash, or null if unavailable (e.g. username doesn't exist)
	 */
	private function getHashedPassword($username) {
		$mysqli = $this->getMySqli();
		if ($mysqli !== null) {
			$username = trim($username);
			$stmt = $mysqli->prepare('SELECT password FROM ' . self::TABLE_NAME . ' WHERE name = ? LIMIT 1');
			$stmt->bind_param('s', $username);
			$stmt->execute();
			$stmt->bind_result($password);
			if ($stmt->fetch()) {
				return $password;
			}
		}
		return null;
	}
}
