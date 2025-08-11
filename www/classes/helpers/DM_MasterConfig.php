<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */
 
/**
 * this is a DataManager instance
 */
require_once ('helpers/DataManager.php');

/**
 * connect to the main master configuration database
 */
class DM_MasterConfig extends DataManager {

    private static $instance;

    public function __construct() {
        parent :: __construct();
        
        $socket = $this->getConfig('VARDIR')."/run/mysql_master/mysqld.sock";
        $this->setOption('SOCKET', $socket);
        $this->setOption('DATABASE', 'st_config');
    }

    public static function getInstance() {
        if (empty (self :: $instance)) {
            self :: $instance = new DM_MasterConfig();
        }
        return self :: $instance;
    }
}
?>
