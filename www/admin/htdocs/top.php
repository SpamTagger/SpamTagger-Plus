<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * This is the controller for the top page
 */

/**
 * requires admin session and view
 */
require_once('admin_objects.php');
require_once("view/Template.php");

/**
 * session globals
 */
global $lang_;
global $admin_;

// create view
$template_ = new Template('top.tmpl');

// prepare replacements
$replace = array(
        "__LANG__" => $lang_->getLanguage(),
        "__USERNAME__" => $admin_->getPref('username'),
        "__LINK_LOGOUT__" => "/admin/logout.php"
);

// output page
$template_->output($replace);
?>