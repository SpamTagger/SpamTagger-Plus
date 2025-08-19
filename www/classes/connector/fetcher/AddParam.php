<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */


/**
 * This class takes care of guessing addresses by adding some parameter to the username
 * @package SpamTagger Plus
 */
 class AddParam extends AddressFetcher {


    public function fetch($username, $domain) {
        $matches = array();
        if (preg_match('/^(\S+)[\@\%](\S+)$/', $username, $matches )) {
          $username = $matches[1];
        }
        // check for NT domains
        if (preg_match('/^\S+\\\\(\S+)$/', $username, $matches)) {
          $username = $matches[1];
        }
        switch ($this->getType()) {
          case 'at_login':
            $add = $username."@".$domain->getPref('name');
            break;
          case 'param_add':
            //@todo this should be taken from a ConnectorSettings object
            list($t1, $t2, $t3, $t4, $t5, $suffix) = split(':', $domain->getPref('auth_param'));
            $add = $username.'@'.$suffix;
            break;
        }
        $this->addAddress($add, $add);
        return $this->getAddresses();
    }

    public function searchUsers($u, $d) {
      return array();
    }

    public function searchEmails($l, $d) {
      return array();
    }

    public function canModifyList() {
        return true;
    }

 }
?>
