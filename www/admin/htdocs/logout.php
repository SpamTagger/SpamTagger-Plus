<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * @abstract This is the admin logout page controller
 */
 
/**
 * requires admin session
 */
require_once("admin_objects.php");
require_once("view/Language.php");
require_once("view/Template.php");

/**
 * session globals
 */
global $lang_;

// create view
$template_ = new Template('logout.tmpl');
// prepare replacements
$replace = array(
	"__ADMIN_BASE_URL__" => $_SERVER['SERVER_NAME']."/admin/",
	"__USER_BASE_URL__" => $_SERVER['SERVER_NAME']
);

// output page
$template_->output($replace);

// actually execute logout
unregisterAll();
?>