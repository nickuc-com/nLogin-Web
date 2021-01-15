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

class AuthMe extends Algorithm {

	/** @var string[] range of characters for salt generation */
	private $CHARS;

	const SALT_LENGTH = 16;

	public function __construct() {
		$this->CHARS = self::initCharRange();
	}

	protected function isValidPassword($password, $hash) {
		// $SHA$salt$hash, where hash := sha256(sha256(password) . salt)
		$parts = explode('$', $hash);
		$count = count($parts);
		return ($count === 4 || $count === 5) && $parts[3] === hash('sha256', hash('sha256', $password) . $parts[2]);
	}

	protected function hash($password) {
		$salt = $this->generateSalt();
		return '$SHA$' . $salt . '$' . hash('sha256', hash('sha256', $password) . $salt) . '$AUTHME';
	}

	/**
	 * @return string randomly generated salt
	 */
	private function generateSalt() {
		$maxCharIndex = count($this->CHARS) - 1;
		$salt = '';
		for ($i = 0; $i < self::SALT_LENGTH; ++$i) {
			$salt .= $this->CHARS[mt_rand(0, $maxCharIndex)];
		}
		return $salt;
	}

	private static function initCharRange() {
		return array_merge(range('0', '9'), range('a', 'f'));
	}

}
