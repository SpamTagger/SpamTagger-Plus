<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * @abstract This is the index page controller
 */
 
/**
 * requires admin session, and view
 */
require_once ("admin_objects.php");
require_once ("view/Template.php");

// create view
$template_ = new Template('index.tmpl');

// prepare replacements
$replace = array (
        "__TOP_PAGE__" => 'top.php', 
        "__NAVIGATION_PAGE__" => 'navigation.php', 
        "__WELCOME_PAGE__" => 'welcome.php'
);

// output page
$template_->output($replace);
?>
