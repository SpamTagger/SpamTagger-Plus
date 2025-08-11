<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * @abstract This is the controller for the force content page
 */
 
/**
 * requires admin session, and content stuff
 */      
require_once('admin_objects.php');
require_once("view/Template.php");
require_once("user/Content.php");

/**
 * session globals
 */
global $lang_;
global $sysconf_;

$res = "BADARGS";
// create, load and try to force Content
$content = new Content();
if (isset($_GET['id']) && preg_match('/^[a-z,A-Z,0-9]{6}-[a-z,A-Z,0-9]{6,11}-[a-z,A-Z,0-9]{2,4}$/', $_GET['id'])) {
  $res = $content->load($_GET['id']);

  if ($res == "OK") { 
    $res = $content->force();
  }
}

// check result
if ($res == "FORCED") {
  $message = $lang_->print_txt('MSGFORCED');
 } else {
  if (!is_object($res) && $lang_->print_txt($res) != "") {
    $message = $lang_->print_txt($res);
  } else {
    $message = $lang_->print_txt('ERRORSENDING')." (".$res.")";
  }
 }

// create view
$template_ = new Template('force_content.tmpl');

// prepare replacements
$replace = array(
  '__MESSAGE__' => $message
);

// output page
$template_->output($replace);
?>
