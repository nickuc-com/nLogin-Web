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

abstract class Algorithm {

	/**
	 * Hashes the given password.
	 *
	 * @param $password string the clear-text password to hash
	 * @return string the resulting hash
	 */
	protected abstract function hash($password);

	/**
	 * Checks whether the given password matches the hash.
	 *
	 * @param $password string the clear-text password
	 * @param $hash string the password hash
	 * @return boolean true if the password matches, false otherwise
	 */
	protected abstract function isValidPassword($password, $hash);

}