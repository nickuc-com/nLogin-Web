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
 * Argon2 hashing class
 * Supports ARGON2I, ARGON2ID, and ARGON2D
 */
class Argon2 extends Algorithm {

	/**
	 * Default algorithm (ARGON2ID is most secure)
	 * 
	 * @var int
	 */
	protected $_algorithm = PASSWORD_ARGON2ID;
	
	/**
	 * Default memory cost (in KiB)
	 * 
	 * @var integer
	 */
	protected $_memoryCost = 65536;
	
	/**
	 * Default time cost (iterations)
	 * 
	 * @var integer
	 */
	protected $_timeCost = 10;
	
	/**
	 * Default threads/parallelism
	 * 
	 * @var integer
	 */
	protected $_threads = 1;

	/**
	 * Hash a string using Argon2
	 * 
	 * @param  string  $password The password to hash
	 * @param  array   $options  Optional hashing options
	 * 
	 * @return string The hashed password
	 */
	public function hash(string $password, array $options = []) {
		$defaultOptions = [
			'memory_cost' => $this->_memoryCost,
			'time_cost' => $this->_timeCost,
			'threads' => $this->_threads
		];
		
		$options = array_merge($defaultOptions, $options);
		
		return password_hash($password, $this->_algorithm, $options);
	}

	/**
	 * Verify a password against an Argon2 hash
	 * 
	 * @param  string $password The plain password
	 * @param  string $hash     The hashed password
	 * 
	 * @return boolean true if the password matches, false otherwise
	 */
	public function verify(string $password, string $hash) {
		// PHP's password_verify handles all Argon2 variants
		return password_verify($password, $hash);
	}

	/**
	 * Check if a hash needs rehashing
	 * 
	 * @param  string $hash The hash to check
	 * 
	 * @return boolean true if rehashing is needed
	 */
	public function needsRehash(string $hash) {
		$options = [
			'memory_cost' => $this->_memoryCost,
			'time_cost' => $this->_timeCost,
			'threads' => $this->_threads
		];
		
		return password_needs_rehash($hash, $this->_algorithm, $options);
	}

}
