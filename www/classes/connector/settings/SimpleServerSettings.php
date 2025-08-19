<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */


/**
 * This class takes care of storing settings of a simple server
 * @package SpamTagger Plus
 */
 class SimpleServerSettings extends ConnectorSettings {

   /**
    * template tag
    * @var string
    */
   protected $template_tag_ = 'SIMPLEAUTH';

    /**
   * Specialized settings array with default values
   * @var array
   */
   protected $spec_settings_ = array(
                              'usessl' => false
                             );
   /**
    * fields type
    * @var array
    */
   protected $spec_settings_type_ = array(
                               'usessl' => array('checkbox', '1')
                               );

 }
?>
