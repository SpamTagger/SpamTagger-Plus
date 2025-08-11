<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

/**
 * include log, system config and session objects
 */ 
require_once('Log.php');        
require_once('variables.php');
require_once('system/SystemConfig.php');
require_once('view/Language.php');
require_once('config/Administrator.php');

/**
 * session objects
 */
global $lang_;
global $sysconf_;
global $admin_;
global $log_;
    
// set log and load SystemConfig singleton
$log_->setIdent('admin');
$sysconf_ = SystemConfig::getInstance();

//check user is logged. Redirect if not
if (!isset($_SESSION['admin'])) {
  header("Location: login.php");
  exit;
} else {
  // load admin session object
  $admin_ = unserialize($_SESSION['admin']);
}
$lang_ = Language::getInstance('admin');

// delete admin session object
function unregisterAll() {
  unset($_SESSION['admin']);
}
?>
