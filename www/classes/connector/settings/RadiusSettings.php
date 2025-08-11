<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */
 
 
/**
 * This class takes care of storing Radius settings
 * @package SpamTagger Plus
 */
 class RadiusSettings extends ConnectorSettings {
   
   /**
    * template tag
    * @var string
    */
   protected $template_tag_ = 'RADIUSAUTH';
   
   /**
   * Specialized settings array with default values
   * @var array
   */
   protected $spec_settings_ = array(
                              'secret' => '',
                              'authtype'   => 'PAP'
                             );
                             
   /**
    * fields type
    * @var array
    */
   protected $spec_settings_type_ = array(
                              'secret' => array('text', 20),
                              'authtype' => array('select', array('PAP' => 'PAP', 'CHAP_MD5' => 'CHAP_MD5', 'MSCHAPv1' => 'MSCHAPv1', 'MSCHAPv2' => 'MSCHAPv2'))
                              );                          

   public function __construct($type) {
      parent::__construct($type);
      $this->setSetting('server', 'localhost');
      $this->setSetting('port', '1645');
   }   
 }
?>
