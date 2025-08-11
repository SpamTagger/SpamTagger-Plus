<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */
 
/**
 * requires PEAR's Auth class
 */
require_once("Auth.php");
 
/**
 * This is the SQLAuthenticator class
 * This will take care of authenticate user against a SQL server
 * @package SpamTagger Plus
 */
class SQLAuthenticator extends AuthManager {
    
    protected $exhaustive_ = true;
    
    function create($domain) {
       require_once('connector/settings/SQLSettings.php');
       if (isset($domain) && $domain->getConnectorSettings()) {
         $settings = $domain->getConnectorSettings();
       } else {
	 $settings = new SQLSettings('local');
       }
       $dsn = $settings->getDSN();
       
       $funct = array ("LoginDialog", "loginFunction");
       $params = array (
                        "dsn"   => $dsn,
                        "table" => $settings->getSetting('table'),
                        "usernamecol" => $settings->getSetting('login_field'),
                        "passwordcol" => $settings->getSetting('password_field'),
                        "cryptType" => $settings->getSetting('crypt_type')
                      );
      $this->auth_ = new Auth('DB', $params, $funct);
      if ($this->auth_ instanceof Auth) {
        $this->setUpAuth();
        return true;
      }
      return false;
    }
    
   public function isExhaustive() {
       if ($this->getType() == 'local') {
           return false;
       }
       return true;
   }
}
?>
