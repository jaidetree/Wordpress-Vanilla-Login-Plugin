<?php
/*
Plugin Name: Vanilla Login System
Plugin URI: http://www.xugostudios.com
Version: 1.0
Author: Jay
Description: Allows us to use Vanilla's Login System

Copyright 2011  Jay Zawrotny  (email: jayzawrotny@gmail.com)

	This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

if( ! class_exists( 'XS_VanillaLogin' ) )
{
	class XS_VanillaLogin
	{
		var $cookie = array();
		var $volatile = array();

		const VCOOKIE_NAME = 'Vxc4f';
		const VCOOKIE_SALT = '22FMK0GSCO';
		const VCOOKIE_DOMAIN = '';
		const VCOOKIE_PATH = '/';
		

		function XS_VanillaLogin()
		{
			$this->cookie = explode( "|", $_COOKIE[self::VCOOKIE_NAME] );
			$this->volatile = explode( "|", $_COOKIE[self::VCOOKIE_NAME . '-Volatile'] );

			var_dump( $this->check_cookie(self::VCOOKIE_NAME) );
		}	
                      
		function check_cookie($CookieName)
		{
			$CookieHashMethod = 'md5';

			if (empty($_COOKIE[$CookieName])) 
			{
				return FALSE;
			}
					  
			$CookieData = explode('|', $_COOKIE[$CookieName]);
			if (count($CookieData) < 5) 
			{
				$this->DeleteCookie($CookieName);
				return FALSE;
			}

			list($HashKey, $CookieHash, $Time, $UserID, $Expiration) = $CookieData;
			if ($Expiration < time() && $Expiration != 0)
			{
				$this->DeleteCookie($CookieName);
				return FALSE;
			}

			$Key = $this->_Hash($HashKey, $CookieHashMethod, self::VCOOKIE_SALT);
			$GeneratedHash = $this->_HashHMAC($CookieHashMethod, $HashKey, $Key);

			if ($CookieHash != $GeneratedHash) 
			{
				$this->DeleteCookie($CookieName);
				return FALSE;
			}

			return TRUE;         
		}


	   /**
		* Returns $this->_HashHMAC with the provided data, the default hashing method
		* (md5), and the server's COOKIE.SALT string as the key.
		*
		* @param string $Data The data to place in the hash.
		*/
		function _Hash($Data, $CookieHashMethod, $CookieSalt) 
		{
			return $this->_HashHMAC($CookieHashMethod, $Data, $CookieSalt);
		}
	   
	   /**
		* Returns the provided data hashed with the specified method using the
		* specified key.
		*
		* @param string $HashMethod The hashing method to use on $Data. Options are MD5 or SHA1.
		* @param string $Data The data to place in the hash.
		* @param string $Key The key to use when hashing the data.
		*/
		function _HashHMAC($HashMethod, $Data, $Key) 
		{
			$PackFormats = array('md5' => 'H32', 'sha1' => 'H40');

			if (!isset($PackFormats[$HashMethod]))
			 return false;

			$PackFormat = $PackFormats[$HashMethod];
			// this is the equivalent of "strlen($Key) > 64":
			if (isset($Key[63]))
			   $Key = pack($PackFormat, $HashMethod($Key));
			else
			   $Key = str_pad($Key, 64, chr(0));

			$InnerPad = (substr($Key, 0, 64) ^ str_repeat(chr(0x36), 64));
			$OuterPad = (substr($Key, 0, 64) ^ str_repeat(chr(0x5C), 64));

			return $HashMethod($OuterPad . pack($PackFormat, $HashMethod($InnerPad . $Data)));
		} 

		function DeleteCookie($CookieName, $Path = NULL, $Domain = NULL) 
		{

			  if (is_null($Path))
				 $Path = VCOOKIE_PATH;

			  if (is_null($Domain))
				 $Domain = VCOOKIE_DOMAIN;
			  
			  $Expiry = strtotime('one year ago');
			  setcookie($CookieName, "", $Expiry, $Path, $Domain);
			  $_COOKIE[$CookieName] = NULL;     
		}
	}
}

if( class_exists( 'XS_VanillaLogin' ) )
{
	$xglogin = new XS_VanillaLogin();
}

/*
if( ! function_exists( 'XS_SetupPage' ) )
{
	function XS_SetupPage()
	{
		global $xgimporter;

		add_management_page( 'XG Import', 'XG Import', 9, basename(__FILE__), array( &$xgimporter, 'showAdminPage' ) );
	}
}
if (isset($xgimporter)) {
	//Actions
	add_action('admin_menu', 'XS_SetupPage');
}
 */
?>
