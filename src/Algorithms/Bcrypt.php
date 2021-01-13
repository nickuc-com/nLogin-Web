<?php
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

/**
 * Bcrypt hashing class
 * 
 * @author Thiago Belem <contato@thiagobelem.net>
 * @link   https://gist.github.com/3438461
 */
class Bcrypt extends Algorithm {

	/**
	 * Default salt prefix
	 * 
	 * @see http://www.php.net/security/crypt_blowfish.php
	 * 
	 * @var string
	 */
    protected static $_saltPrefix = '2a';
	 
	/**
	 * Default hashing cost (4-31)
	 * 
	 * @var integer
	 */
    protected static $_defaultCost = 14;
 
	/**
	 * Salt limit length
	 * 
	 * @var integer
	 */
    protected static $_saltLength = 22;

    /**
	 * Hash a string
	 * 
	 * @param  string  $string The string
	 * @param  integer $cost   The hashing cost
	 * 
	 * @see    http://www.php.net/manual/en/function.crypt.php
	 * 
	 * @return string
	 */
    public function hash($string, $cost = null) {
        if (empty($cost)) {
            $cost = self::$_defaultCost;
        }
 
        // Salt
        $salt = $this->generateRandomSalt();
 
        // Hash string
        $hashString = $this->__generateHashString((int)$cost, $salt);
 
        return crypt($string, $hashString);
    }

    /**
	 * Check a hashed string
	 * 
	 * @param  string $string The string
	 * @param  string $hash   The hash
	 * 
	 * @return boolean
	 */
    public function isValidPassword($password, $hash) {
        return (crypt($password, $hash) === $hash);
    }

    /**
	 * Generate a random base64 encoded salt
	 * 
	 * @return string
	 */
    private function generateRandomSalt() {
        // Salt seed
        $seed = uniqid(mt_rand(), true);
 
        // Generate salt
        $salt = base64_encode($seed);
        $salt = str_replace('+', '.', $salt);
 
        return substr($salt, 0, self::$_saltLength);
    }
 
	/**
	 * Build a hash string for crypt()
	 * 
	 * @param  integer $cost The hashing cost
	 * @param  string $salt  The salt
	 * 
	 * @return string
	 */
    private function __generateHashString($cost, $salt) {
        return sprintf('$%s$%02d$%s$', self::$_saltPrefix, $cost, $salt);
    }

}
