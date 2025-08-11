<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * Email warnlist form
 */

class Default_Form_Manage_EmailWarnlist extends Default_Form_ElementList
{
	protected $_email;
	protected $_panelname = 'warnlist';
	public $_wwlist = array();
	
	public function __construct($email)
	{
	    $this->_email = $email;
	    $wwelement = new Default_Model_WWElement();
	    $this->_wwlist = $wwelement->fetchAll($this->_email->getParam('address'), 'warn');

	    parent::__construct($this->_wwlist, 'Default_Model_WWElement');
	}
	
	
	public function init()
	{
		parent::init();
		$this->setMethod('post');
			
		$t = Zend_Registry::get('translate');

		$this->setAttrib('id', 'email_form');
	    $panellist = new Zend_Form_Element_Select('emailpanel', array(
            'required'   => false,
            'filters'    => array('StringTrim')));
	    ## TODO: add specific validator
	    $panellist->addValidator(new Zend_Validate_Alnum());
        
        foreach ($this->_email->getConfigPanels() as $panel => $panelname) {
        	$panellist->addMultiOption($panel, $panelname);
        }
        $panellist->setValue($this->_panelname);
        $this->addElement($panellist);
        
        $panel = new Zend_Form_Element_Hidden('panel');
		$panel->setValue($this->_panelname);
		$this->addElement($panel);
		$name = new Zend_Form_Element_Hidden('address');
		$name->setValue($this->_email->getParam('address'));
		$this->addElement($name);
		
	}
	
	public function setParams($request, $email) {
		$this->setAddedValues(array('recipient' => $email->getParam('address'),'type' => 'warn'));
		$this->manageRequest($request);
		$this->addFields($this);
		return true;
	}

}