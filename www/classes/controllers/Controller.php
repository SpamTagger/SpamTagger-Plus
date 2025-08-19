<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * This is the main controller class, instantiates specific controllers
 */

/**
 * page controller class
 * this class is a factory and mother class for all page controllers
 *
 * @package SpamTagger Plus
 */
class Controller {

  public function __construct() {}

  static public function factory($class) {
    if (@include_once('controllers/user/'.$class.".php")) {
      return new $class();
    }
    return new Controller();
  }

  public function processInput() {
  }

  public function addReplace($replace, $template) {
  	return $replace;
  }
}
?>
