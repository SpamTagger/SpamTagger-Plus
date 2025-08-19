<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * This is the controller for the page for not allowed accesses
 */

/**
 * require admin session and view
 */
require_once("admin_objects.php");
require_once("view/Template.php");

/**
 * session globals
 */
global $lang_;

// create view
$template_ = new Template('notallowed.tmpl');

// prepare replacements
$replace = array(
        "__LANG__" => $lang_->getLanguage()
);

// output page
$template_->output($replace);
?>
