<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * @abstract This is the documentation window controller
 */
 
/**
 * requires admin session, and documentation stuff
 */
require_once('variables.php');
require_once('admin_objects.php');
require_once('view/Documentor.php');
require_once('view/Template.php');

// create Documentor object
$doc = new Documentor();
// create view
$template = new Template('help.tmpl');
 
// prepare replacements 
$replace = array(
        '__DOC_TEXT__' => $template->processText($doc->getHelpText($_GET['s']), array())
);

// output page
$template->output($replace);
?>