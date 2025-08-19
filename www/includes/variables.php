<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

/**
 * we do set some global variables here
 */

// debug or not
ini_set('error_reporting', E_ALL & ~E_STRICT & ~E_DEPRECATED);
ini_set('display_errors', 0);

// do the logging stuff as soon as possible
require_once('Log.php');
$STLOGLEVEL = PEAR_LOG_WARNING;  // normal is: PEAR_LOG_WARNING or PEAR_LOG_INFO
require_once('helpers/DataManager.php');
require_once('system/SystemConfig.php');
$conf_ = DataManager::getFileConfig(SystemConfig::$CONFIGFILE_);
$log_ = Log::singleton('file', $conf_['VARDIR']."/log/spamtagger/webgui.log", 'none', null, $STLOGLEVEL);
global $log_;

## set the timezone
if (file_exists('/etc/timezone')) {
  $timezone = file_get_contents('/etc/timezone');
  if (is_string($timezone)) {
    date_default_timezone_set(preg_replace('/\s+/', '', $timezone));
  }
}
?>
