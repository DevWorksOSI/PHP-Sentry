# PHP-Sentry
A Website Minuteman, Standing Tall, Vigilant and always on Duty. PHP Class Driven Security for PHP Websites

## Database
 - There is no SQL file for you to cheat with, do it right!
 - Setup a table table called banned_ip
 - Add id, ip, source, bann_date columns
 - Make sure id is int or mediumint 1, index and auto increment
 - Make sure bann_date is DATETIME
 - ip should be set to VARCHAR(100)
 - source is VARCHAR(50)
 
## Config
 - Set your database username, password, database name and httpbl key in config.php
 
## Using
- Sentry is loaded in core/loader.php
- Include core/loader.php in your index or header
- Upload everything to your web root
- Check PHP Logs
- If all is good, enjoy the peace of mind that PHP Sentry provides by keeping your domain secure.
