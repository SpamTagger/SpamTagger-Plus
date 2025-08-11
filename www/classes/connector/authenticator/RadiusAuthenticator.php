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
 * This is the RadiusAuthenticator class
 * This will take care of authenticate user against a Radius server
 * @package SpamTagger Plus
 */
class RadiusAuthenticator extends AuthManager {
    
    protected $exhaustive_ = true;
    
    function create($domain) {
       $settings = $domain->getConnectorSettings();
       if (! $settings instanceof RadiusSettings) {
            return false;
        }
       
       $ser = array(  array($settings->getSetting('server'), $settings->getSetting('port'), $settings->getSetting('secret')) );
       
       $funct = array ("LoginDialog", "loginFunction");
       $params = array (
                        "servers" => $ser,
                        "authtype" => $settings->getSetting('authtype')
                      );
      $this->auth_ = new Auth('RADIUS', $params, $funct);
      if ($this->auth_ instanceof Auth) {
        $this->setUpAuth();
        return true;
      }
      return false;
    }
}
?>
