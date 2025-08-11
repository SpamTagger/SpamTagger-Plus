<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * This is the controller for the logout page
 */
 
if ($_SERVER["REQUEST_METHOD"] == "HEAD") {
  return 200;
}

/**
 * require session
 */ 
require_once("objects.php");
require_once("view/LoginDialog.php");
require_once("view/Template.php");
require_once("config/HTTPDConfig.php");
global $sysconf_;
global $lang_;

// create view
$template_ = new Template('logout.tmpl');

$http = new HTTPDConfig();
$http->load();

$http_sheme = 'http';
$port = '';
if ($http->getPref('use_ssl')) {
	$http_sheme = 'https';
	if ($http->getPref('https_port') != 443) {
		$port = ':' . $http->getPref('https_port');
	}
} else {
	if ($http->getPref('http_port') != 80) {
		$port = ':' . $http->getPref('http_port');
	}
}

$stlink="https://spamtagger.org";
$stlinklabel="spamtagger.org";

// prepare replacements
$replace = array(
    "__BASE_URL__" => $_SERVER['SERVER_NAME'],
    "__BEENLOGGEDOUT__" => $lang_->print_txt_param('BEENLOGGEDOUT', $http_sheme."://".$_SERVER['SERVER_NAME'].$port),
    "__STLINK__" => $stlink,
    "__STLINKLABEL__" => $stlinklabel,
);
//display page
$template_->output($replace);

// and do the job !
unregisterAll();
?>
