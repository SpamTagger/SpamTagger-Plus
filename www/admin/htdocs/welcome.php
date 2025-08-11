<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * This is the controller for the welcome page
 */

/**
 * require administrative access
 */
require_once("admin_objects.php");
require_once("view/Template.php");
require_once("system/Integrator.php");
/**
 * session globals
 */ 
global $lang_;
global $sysconf_;

// create view
$template_ = new Template('welcome.tmpl');

$integrator = new Integrator();

// prepare replacements
$replace = array(
        "__LANG__" => $lang_->getLanguage(),
        "__DATE__" => strftime("%d.%m.%Y %H:%M.%S"),
        "__HOSTID__" => $sysconf_->getPref('hostid'),
        "__MASTER__" => isMaster(),
        "__INT_WEBSITE__" => $integrator->getInfo('SiteInternet'),
        "__INT_COMPANY__" => $integrator->getInfo('Company'),
        "__INT_TECHNAME__" => $integrator->getInfo('Surname_T')." ".$integrator->getInfo('Name_T'),
        "__INT_TECHMAIL__" => $integrator->getInfo('Mail_T'),
        "__INT_TECHPHONE__" => $integrator->getInfo('Phone_T')
);

// output page
$template_->output($replace);

/**
 * return master/slave status of the host
 * @return  string  status
 */
function isMaster() {
  global $lang_;
  global $sysconf_;
 
  if ($sysconf_->ismaster_ < 1) {
    return $lang_->print_txt('ISNOTAMASTER');
  }
  return $lang_->print_txt("ISAMASTER");
}
?>
