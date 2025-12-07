<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * This is the controller for the main index page
 * It is responsible for the frameset
 */

/**
 * require valid session
 */
require_once("objects.php");
require_once("view/Template.php");
require_once("system/SystemConfig.php");
global $sysconf_;
global $lang_;

/**
 * out if we are not on a source host
 */
if ($sysconf_->issource_ < 1) {
  exit;
}

// create view
$template_ = new Template('index.tmpl');

$firstpage = 'quarantine.php';
#if (!$user_->hasPrefs()) {
#  $firstpage = 'configuration.php?t=int';
#}

$replace = array(
        "__LANG__" => $lang_->getLanguage(),
        "__NAVIGATION_PAGE__" => 'navigation.php?m=q',
        "__QUARANTINE_PAGE__" => 'quarantine.php',
        "__PARAMETERS_PAGE__" => 'parameters.php',
        "__SUPPORT_PAGE__" => 'support.php',
        "__FIRST_PAGE__" => $firstpage
);

// display page
$template_->output($replace);
?>