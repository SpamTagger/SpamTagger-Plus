<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */


/**
 * This class takes care of storing Tequila settings
 * @package SpamTagger Plus
 */
 class TequilaSettings extends ConnectorSettings {

   /**
    * template tag
    * @var string
    */
   protected $template_tag_ = 'TEQUILAAUTH';

   /**
   * Specialized settings array with default values
   * @var array
   */
   protected $spec_settings_ = array(
                              'usessl' => false,
                              'fields' => '',
                              'url' => '',
                              'loginfield' => '',
                              'realnameformat' => '',
                              'allowsfilter' => ''
                             );

   /**
    * fields type
    * @var array
    */
   protected $spec_settings_type_ = array(
                              'usessl' => array('checkbox', 'true'),
                              'url' => array('text', 20),
                              'fields' => array('text', 30),
                              'loginfield' => array('text', 20),
                              'realnameformat' => array('text', 30),
                              'allowsfilter' => array('text', 30)
                             );

   public function __construct($type) {
      parent::__construct($type);
      $this->setSetting('server', 'localhost');
      $this->setSetting('port', '80');
   }
 }
?>
