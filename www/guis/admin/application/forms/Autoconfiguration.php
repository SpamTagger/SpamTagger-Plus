<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Mentor Reka
 * @copyright 2025, SpamTagger
 *
 * Auto-configuration settings form
 */

class Default_Form_Autoconfiguration extends ZendX_JQuery_Form
{
	private $ST_AUTOCONF_TAG_FILE="/spool/spamtagger/st-autoconf";

	protected $_autoconfmanager;

	public function __construct($autoconf) {
		$this->_autoconfmanager = $autoconf;
		parent::__construct();
	}


	public function init()
	{
		$t = Zend_Registry::get('translate');
		$layout = Zend_Layout::getMvcInstance();
	    	$view=$layout->getView();

		$this->setMethod('post');
		$this->setAttrib('id', 'autoconfiguration_form');

		require_once('SpamTagger/Config.php');
	        $config = new SpamTagger_Config();
		$autoconf_enabled = file_exists($config->getOption('VARDIR').$this->ST_AUTOCONF_TAG_FILE);

        	$autoconf = new  Zend_Form_Element_Checkbox('autoconfiguration', array(
            		'label' => "Enable auto-configuration :",
		    	'required' => false));
	   	$autoconf->setValue($autoconf_enabled);
		$this->addElement($autoconf);

		$submit = new Zend_Form_Element_Submit('submit', array(
		     'label'    => $t->_('Submit')));
		$this->addElement($submit);

	}

}
