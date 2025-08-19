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
 * connect to the slave spool database
 */
class DM_SlaveSpool extends DataManager {

    private static $instance;

    public function __construct() {
        parent :: __construct();

        $socket = $this->getConfig('VARDIR')."/run/mysql_slave/mysqld.sock";
        $this->setOption('SOCKET', $socket);
        $this->setOption('DATABASE', 'st_spool');
    }

    public static function getInstance() {
        if (empty (self :: $instance)) {
            self :: $instance = new DM_SlaveSpool();
        }
        return self :: $instance;
    }

}
?>
