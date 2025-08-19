<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */


/**
 * This class takes care of reformatting the login passed by adding the domain.
 * @package SpamTagger Plus
 */
class DomainAddFormatter extends LoginFormatter {

     public function format($login_given, $domain_name) {
       require_once('system/SystemConfig.php');
       $sysconf = SystemConfig::getInstance();
       if (!in_array($domain_name, $sysconf->getFilteredDomains())) {
         return null;
       }
       $separator = '';
       switch ($this->getType()) {
         case 'at_add':
           $separator = '@';
           break;
         case 'percent_add':
           $separator = '%';
           break;
       }
       $matches = array();
       if (preg_match('/^(\S+)[\@\%](\S+)$/', $login_given, $matches)) {
         return $matches[1].$separator.$domain_name;
       }
       if ($login_given == "") {
        return false;
       }
       return $login_given.$separator.$domain_name;
     }
}
?>
