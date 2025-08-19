<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Registration form
 */

class Default_Form_ChangeHostId extends ZendX_JQuery_Form
{

	protected $_changeHostIdmgr;
	public function __construct($mgr) {
		$this->_changeHostIdmgr = $mgr;
		parent::__construct();
	}


	public function init()
	{
		$t = Zend_Registry::get('translate');
		$layout = Zend_Layout::getMvcInstance();
	    	$view=$layout->getView();

		$this->setMethod('post');

		$config = new SpamTagger_Config();
		$hid = $config->getOption('HOSTID');

		$host_id = new  Zend_Form_Element_Text('host_id', array(
            		'label' => $t->_('Host ID'). " :",
                	'required' => true));
            	$host_id->setValue($hid);
            	$host_id->addValidator(new Zend_Validate_Digits());
            	$this->addElement($host_id);

		$this->setAttrib('id', 'changehostid_form');

	        $submit = new Zend_Form_Element_Submit('changehostid', array(
		     'label'    => $t->_('Submit'),
		     'attribs'    => $attribs));
	    	$this->addElement($submit);
	}

}
