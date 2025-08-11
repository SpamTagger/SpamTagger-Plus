<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */
 
/**
 * this is a preference handler
 */
 require_once('helpers/PrefHandler.php');

/**
 * This class contains DNS lists information
 */
class DNSList extends PrefHandler {

    /**
     * scanner properties
     * @var array
     */
	private $pref_ = array(
                      'name' => '',
		              'url' => '',
                      'type' => '',
                      'active' => 1,
		              'comment' => '',
	                 );


/**
 * constructor
 */
public function __construct() {
   $this->addPrefSet('dnslist', 'l', $this->pref_);
}

/**
 * load datas from database
 * @param  $listname      string  list name
 * @return                boolean  true on success, false on failure
 */
public function load($list_name) {
  $where = "name='$list_name'";
  return $this->loadPrefs('', $where, false);
}

/**
 * save datas to database
 * @return    string  'OKSAVED' on success, error message on failure
 */
public function save() {
  $where = "name='".$this->getPref('name')."'";
  return $this->savePrefs('', $where, '');
}

public function isEnabled($givenlist) {
  return preg_match("/\b".$this->getPref('name')."\b/", $givenlist);
}

}
?>
