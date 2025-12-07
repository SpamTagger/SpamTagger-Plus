<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

/**
 * This class is only a settings wrapper for the apache configuration
 */
class HTTPDConfig extends PrefHandler {

  /**
   * httpd settings
   * @var array
   */
  private $pref_ = array(
     'use_ssl' => 'true',
     'serveradmin' => 'postsource@localhost',
     'servername' => 'localhost',
     'timeout' => 300,
     'keepalivetimeout' => 100,
     'min_servers' => 3,
     'max_servers' => 10,
     'start_servers' => 5,
     'http_port' => 80,
     'https_port' => 443,
     'certificate_file' => 'default.pem'
   );

/**
 * constructor
 */
public function __construct() {
    $this->addPrefSet('httpd_config', 'c', $this->pref_);
}

/**
 * load settings
 * @return  boolean true on success, false on failure
 */
public function load() {
  return $this->loadPrefs('', '1=1', false);
}

}
?>
