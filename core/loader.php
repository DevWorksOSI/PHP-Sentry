<?php

/*
 * Loader
 *
*/

spl_autoload_register(function($name){
        require_once 'app/'.str_replace('\\','/',$name).'.php';
});


use database\db;
use sentry\security;

$db = new db();
$sentry = new security();

// Load Sentry functions
$sentry->httpbl_check();
$ip = $sentry->get_real_ip();
$sentry->ip_location($ip);
$sentry->check_ban($ip);
