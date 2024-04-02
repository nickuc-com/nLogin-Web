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

class Sha256 extends Algorithm {

	/**
	 * salt length
	 */
	protected $SALT_LENGTH = 24;

	private $CHARS; 

	public function __construct() {
		$this->CHARS = implode('', range('A', 'Z')) . implode('', range(0, 9));
	}

	public function hash(string $password) {
		$salt = $this->generateSalt();
		return '$SHA256$' . hash('sha256', hash('sha256', $password) . $salt) . '$' . $salt;
	}

	public function verify(string $password, string $hash) {
		$parts = explode('$', $hash);
		$partsLength = count($parts);
		switch ($partsLength) {
			case 3: // old format
				$saltParts = explode('@', $hash);
				$salt = $saltParts[1];
				return $parts[2] . '@' . $salt === hash('sha256', hash('sha256', $password) . $salt);

			case 4: // new format
				return $parts[2] === hash('sha256', hash('sha256', $password) . $parts[3]);
			
			default:
				throw new Exception("invalid hash parts length! length=" . $partsLength . ', raw="' . $hash . '"');
		}
	}

	/**
	 * @return string randomly generated salt
	 */
	private function generateSalt() {
		$maxCharIndex = strlen($this->CHARS) - 1;
		$salt = '';
		for ($i = 0; $i < self::$SALT_LENGTH; ++$i) {
			$salt .= $this->CHARS[mt_rand(0, $maxCharIndex)];
		}
		return $salt;
	}

}
