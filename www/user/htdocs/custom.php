<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * This is the controller for a custom page
 */

/**
 * require session
 */ 
require_once("objects.php"); 
require_once("view/Template.php");

$template = 1;
// check parameters
if (!isset($_GET['t']) || !is_numeric($_GET['t']) ) {
  die ("BADPARAMS");
}
// get the template file to use
$template = $_GET['t'];

// create view
$template_ = new Template("custom_$template.tmpl");

// prepare replacements
$replace = array(
	"__LANG__" => $lang_->getLanguage(),
	"__PRINT_USERNAME__" => $user_->getPref('username'),
	"__PRINT_MAINADDRESS__" => $user_->getMainAddress()
);
// display page
$template_->output($replace);
?>
