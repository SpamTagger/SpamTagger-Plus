<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * This is the controler for the remove address page
 */

if ($_SERVER["REQUEST_METHOD"] == "HEAD") {
  return 200;
}

/**
 * require valid session
 */
require_once('objects.php');
require_once("view/Template.php");
global $sysconf_;
global $lang_;
global $user_;

// check parameters
if (!isset($_GET['add']) || $_GET['add'] == "") {
  die ("BADPARAMS");
}
$add = urldecode($_GET['add']);
$message = $lang_->print_txt_param('REMALIASCONFIRM', $add);
// check if user has confirmed
if (isset($_GET['doit'])) {
  // then do it !
  $message = "<font color=\"red\">".$lang_->print_txt('CANNOTREMOVEMAINADD')."</font><br/><br/>";
  if ($user_->removeAddress($add)) {
    $message = "<font color=\"red\">".$lang_->print_txt_param('ALIASREMOVED', $add)."</font><br/><br/>";
  }
}

// create view
$template_ = new Template('rem_address.tmpl');
$params = $_GET;
$params['doit'] = '1';
$replace = array(
        '__INCLUDE_JS__' =>
"<script type=\"text/javascript\" language=\"javascript\">
    function confirm() {
        window.location.href=\"".$_SERVER['PHP_SELF']."?add=$add&doit=1\";
    }
</script>",
        '__MESSAGE__' => $message,
        '__CONFIRM_BUTTON__' => confirm_button()
);
// display page
$template_->output($replace);

/**
 * return the html string for the confirmation button if needed
 * @return  string html button string
 */
function confirm_button() {
  $lang_ = Language::getInstance('user');
  if (! isset($_GET['doit'])) {
     return "&nbsp;<input type=\"button\" onClick=\"javascript:confirm()\" value=\"".$lang_->print_txt('CONFIRM')."\" />";
  }
  return ;
}
?>
