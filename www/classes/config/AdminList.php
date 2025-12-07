<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

/**
 * this is as list
 */
require_once('helpers/ListManager.php');

/**
 * This will takes care of fetching list of administrators
 */
class AdminList extends ListManager
{

/**
 * load adminsitrator from database
 * @return  boolean  true on success, false on failure
 */
public function Load() {
  require_once('helpers/DM_SlaveConfig.php');
  $db_replicaconf = DM_SlaveConfig :: getInstance();

  $query = "SELECT username FROM administrator";
  $row = $db_replicaconf->getList($query);
  foreach( $row as $admin) {
    $this->setElement($admin, $admin);
  }
  return true;
}

}
?>
