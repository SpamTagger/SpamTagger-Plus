<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */
 
 
/**
 * This class takes care of reformatting the login passed by removing any domain eventually given.
 * @package SpamTagger Plus
 */
class SimpleFormatter extends LoginFormatter {
     
     
     public function format($login_given, $domain_name) {
       $matches = array();
       if (preg_match('/^(\S+)[\@\%](\S+)$/', $login_given, $matches)) {
        return $matches[1];
       }
       return $login_given; 
     }
}
?>
