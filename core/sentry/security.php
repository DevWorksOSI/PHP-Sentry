<?php

namespace sentry;

require_once(APPROOT .'/config.php'); // Config file

// We need the database
use database\db;


class security
{
        /*
         * httpbl_config()
         * Get httpbl_KEY from config.php
         * You key can be obtained from projecthoneypot.org
        */
	private function httpbl_config()
	{
		$this->httpbl_key = httpBL_KEY;
	}
	
	/*
	 * redirect
	 * usage; $security->redirect_to("location");
	 * will exit on completion
	*/
	public function redirect_to($new_location)
	{
		header("Location: " . $new_location);
		exit;
	}
	
	/*
	 * httpbl_check
	 * gets the IP from get_real_ip()
	 * checks it against dnsbl.httpbl.org
	 * if it returns as a spammer, or harvester, ban it
	 * Reporting source is HTTPBL
	 * requires httpbl key from projecthoneypot.org
	*/
	public function httpbl_check()
	{
		// Initialize values
		//setup();
		$apikey = $this->httpbl_config();
		
		// IP to test from get_real_ip()
		$ip = $this->get_real_ip();
		
		// build the lookup DNS query
		// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.httpbl.org'
		$lookup = $apikey . '.' . implode('.', array_reverse(explode ('.', $ip ))) . '.dnsbl.httpbl.org';
		
		// check query response
		$result = explode( '.', gethostbyname($lookup));
		
		if ($result[0] == 127)
		{
			// query successful !
			$activity = $result[1];
			$threat = $result[2];
			$type = $result[3];
			
			$source = 'HTTPBL';
			
			if ($type & 0) $typemeaning .= 'Search Engine, ';
			if ($type & 1) $typemeaning .= 'Suspicious, ';
			if ($type & 2) $typemeaning .= 'Harvester, ';
			if ($type & 4) $typemeaning .= 'Comment Spammer, ';
			$typemeaning = trim($typemeaning,', ');
			
			if ($type >= 4 && $threat > 0)
			{
				$this->ban_ip($ip, $source);
			}
			if($type < 4 && $threat > 20)
			{
				$this->ban_ip($ip, $source);
			}
		}
	}
	
	/*
	 * Get Real IP
	 * Diggs deep to get the visitors actual ip address
	 * Doesnt matter if it's Spoofed or behind a VPN
	*/
	public function get_real_ip()
	{
		if (isset($_SERVER))
		{
			if (isset($_SERVER["HTTP_X_FORWARDED_FOR"]))
			{
				return $_SERVER["HTTP_X_FORWARDED_FOR"];
			}
			if (isset($_SERVER["HTTP_CLIENT_IP"]))
			{
				return $_SERVER["HTTP_CLIENT_IP"];
			}

			return $_SERVER["REMOTE_ADDR"];
		}

		if (getenv('HTTP_X_FORWARDED_FOR'))
        {
			return getenv('HTTP_X_FORWARDED_FOR');
		}
		if (getenv('HTTP_CLIENT_IP'))
        {
			return getenv('HTTP_CLIENT_IP');
		}
		return getenv('REMOTE_ADDR');
	}
	
	/*
	 * ip_location($ip)
	 * Reporting Source is Sentry
	 * gets the IP from get_real_ip
	 * Runs it against source in lib/ip_files
	 * Returns the IP's location by country
	 * If Russia, China, Afghanistan, North Korea or Iraq -> ban immediately
	 * Add or delete as needed based on your desires
	*/
	public function ip_location($ip)
	{
	   $source = 'Sentry';
		$numbers = preg_split( "/\./", $ip);    
		include("lib/ip_files/".$numbers[0].".php");
		$code=($numbers[0] * 16777216) + ($numbers[1] * 65536) + ($numbers[2] * 256) + ($numbers[3]);    
		foreach($ranges as $key => $value)
		{
			if($key<=$code)
			{
				if($ranges[$key][0]>=$code){$country=$ranges[$key][1];break;}
            }
		}
		if ($country=="")
		{
			$country="unkown";
		}
		
		if($country == "CN")
		{
			$this->ban_ip($ip, $source);
			$this->redirect_to("https://www.projecthoneypot.org");
		}
		elseif($country == "RU")
		{
			$this->ban_ip($ip, $source);
		}
		elseif($country == "AF")
		{
			$this->ban_ip($ip);
			$this->redirect_to("https://www.projecthoneypot.org");
		}
		elseif($country == "IQ")
		{
			$this->ban_ip($ip, $source);
			$this->redirect_to("https://www.projecthoneypot.org");
		}
		elseif($country == "KP")
		{
			$this->ban_ip($ip, $source);
			$this->redirect_to("https://www.projecthoneypot.org");
		}
		elseif($country == "IR")
		{
			$this->ban_ip($ip, $source);
			$this->redirect_to("https://www.projecthoneypot.org");
		}
		else
		{
			return $country;
		}
	}
	
	/*
	 * check_ban($ip)
	 * Gets the IP from get_real_ip()
	 * Checks banned table to see if the IP is present
	 * redirects if found
	 * Never allowing this person on your site.
	 * @ ip
	*/
	public function check_ban($ip)
	{
		$db = new db();
		$query = "SELECT * FROM banned_ip WHERE ip = '$ip'";
		$result = $db->query($query);
		$banned = $db->rows($result);
		if($banned == true)
		{
			$this->redirect_to("https://www.projecthoneypot.org");
		}
	}
	
	/*
	 * bann_ip()
	 * get the IP address from the source function (httpbl_check() and ip_location($ip)
	 *
	 * @ ip
	 * @ source
	 * Source is HTTPBL or Sentry
	*/
	public function ban_ip($ip, $source)
	{
		$db = new db();
		$query = "INSERT INTO banned_ip (ip, source, bann_date) VALUES ('$ip', '$source', now())";
		$result = $db->query($query);
		return $result;
		$this->redirect_to("https://www.projecthoneypot.org");
	}
	
	/*
	 * Count IP addresses
	 * Use in Dashboard or Site Front-End PHP Sentry Information
	*/
	public function count_ips()
	{
	   $db = new db();
	   $query = "SELECT count(*) as total from banned_ip";
	   $result = $db->query($query);
	   $data = $db->fetch_assoc($result);
	   $ip_count = $data['total'];
	   return $ip_count;
	}
	
	/* 
	 * Display Last 5 IP's
	*/
	public function last_Five()
	{
	   $db = new db();
	   $query = "SELECT ip FROM banned_ip ORDER BY id DESC LIMIT 5";
	   $result = $db->query($query);
	   $data = $db->fetch_assoc($result);
	   
	   // Return an array, use foreach
	   return $data;
	}
}

?>
