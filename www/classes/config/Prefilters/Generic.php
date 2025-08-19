<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

/**
 * this is a preference handler
 */
 require_once('helpers/PrefHandler.php');

/**
 * This class is only a settings wrapper for the PreFilter modules configuration
 */
class Generic extends PreFilter {

public function subload() {}

public function addSpecPrefs() {}

public function getSpecificTMPL() {
  return "";
}

public function getSpeciticReplace($template, $form) {
  return array();
}

public function subsave($posted) {}
}
?>
