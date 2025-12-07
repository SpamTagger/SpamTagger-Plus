<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 */

class Default_Form_DomainAdvanced extends Zend_Form {
	protected $_domain;
	protected $_panelname = 'advanced';

	public function __construct($domain) {
	    $this->_domain = $domain;

	    parent::__construct();
	}


	public function init() {
		$this->setMethod('post');

		$t = Zend_Registry::get('translate');
		$user_role = Zend_Registry::get('user')->getUserType();

		$this->setAttrib('id', 'domain_form');
		$panellist = new Zend_Form_Element_Select('domainpanel', array(
			'required'   => false,
			'filters'    => array('StringTrim'))
		);
		## TODO: add specific validator
		$panellist->addValidator(new Zend_Validate_Alnum());

		foreach ($this->_domain->getConfigPanels() as $panel => $panelname) {
			$panellist->addMultiOption($panel, $panelname);
		}
		$panellist->setValue($this->_panelname);
		$this->addElement($panellist);

		$panel = new Zend_Form_Element_Hidden('panel');
		$panel->setValue($this->_panelname);
		$this->addElement($panel);
		$name = new Zend_Form_Element_Hidden('name');
		$name->setValue($this->_domain->getParam('name'));
		$this->addElement($name);

		$domainname = new  Zend_Form_Element_Text('domainname', array(
			'label'   => $t->_('Domain name')." :",
			'required' => false,
			'filters'    => array('StringToLower', 'StringTrim'))
		);
		$domainname->setValue($this->_domain->getParam('name'));
		require_once('Validate/DomainName.php');
		$domainname->addValidator(new Validate_DomainName());
		$this->addElement($domainname);

		$wwelement = new Default_Model_WWElement();
		require_once('Validate/IpList.php');

		$block_ip_dom = new Zend_Form_Element_Textarea('block_ip_dom', array(
			'label'		=>  $t->_('Blocklist those IPs at SMTP stage')." :",
			'title'		=> $t->_("List of IPs or subnets to be rejected at SMTP stage for the current domain"),
			'required'	=> false,
			'rows'		=> 5,
			'cols'		=> 30,
			'filters'	=> array('StringToLower', 'StringTrim'))
		);
		$block_ip_dom->addValidator(new Validate_IpList());
		$block_ip_dom->setValue($wwelement->fetchAllField($this->_domain->getParam('name'), 'block-ip-dom', 'sender'));
	        if ($user_role != 'administrator') {
			$block_ip_dom->setAttrib('disabled', true);
			$block_ip_dom->setAttrib('readonly', true);
		}
		$this->addElement($block_ip_dom);

		$spam_ip_dom = new Zend_Form_Element_Textarea('spam_ip_dom', array(
			'label'    =>  $t->_('Blocklist those IPs at AntiSpam stage')." :",
			'title' => $t->_("List of IPs or subnets to be blocked at AntiSpam stage for the current domain"),
			'required'   => false,
			'rows' => 5,
			'cols' => 30,
			'filters'    => array('StringToLower', 'StringTrim')));
		$spam_ip_dom->addValidator(new Validate_IpList());
		$spam_ip_dom->setValue($wwelement->fetchAllField($this->_domain->getParam('name'), 'spam-ip-dom', 'sender'));
	        if ($user_role != 'administrator') {
			$spam_ip_dom->setAttrib('disabled', true);
			$spam_ip_dom->setAttrib('readonly', true);
		}
		$this->addElement($spam_ip_dom);

		$want_ip_dom = new Zend_Form_Element_Textarea('want_ip_dom', array(
			'label'    =>  $t->_('Wantlist those IPs at SMTP stage')." :",
			'title' => $t->_("List of IPs or subnets to be wantlisted at SMTP stage for the current domain"),
			'required'   => false,
			'rows' => 5,
			'cols' => 30,
			'filters'    => array('StringToLower', 'StringTrim')));
		$want_ip_dom->addValidator(new Validate_IpList());
		$want_ip_dom->setValue($wwelement->fetchAllField($this->_domain->getParam('name'), 'want-ip-dom', 'sender'));
	        if ($user_role != 'administrator') {
			$want_ip_dom->setAttrib('disabled', true);
			$want_ip_dom->setAttrib('readonly', true);
		}
		$this->addElement($want_ip_dom);


		$wh_spamc_ip_dom = new Zend_Form_Element_Textarea('wh_spamc_ip_dom', array(
			'label'    =>  $t->_('Wantlist those IPs at AntiSpam stage')." :",
			'title' => $t->_("List of IPs or subnets to be wantlisted at AntiSpam stage for the current domain"),
			'required'   => false,
			'rows' => 5,
			'cols' => 30,
			'filters'    => array('StringToLower', 'StringTrim')));
		$wh_spamc_ip_dom->addValidator(new Validate_IpList());
		$wh_spamc_ip_dom->setValue($wwelement->fetchAllField($this->_domain->getParam('name'), 'wh-spamc-ip-dom', 'sender'));
	        if ($user_role != 'administrator') {
			$wh_spamc_ip_dom->setAttrib('disabled', true);
			$wh_spamc_ip_dom->setAttrib('readonly', true);
		}
		$this->addElement($wh_spamc_ip_dom);



		$submit = new Zend_Form_Element_Submit('submit', array(
			'label'    => $t->_('Submit'))
		);
	        if ($user_role != 'administrator') {
			$submit->setAttrib('disabled', true);
			$submit->setAttrib('readonly', true);
		}
		$this->addElement($submit);
	}

	public function setParams($request, $domain) {
		$wwelement = new Default_Model_WWElement();
		$wwelement->setBulkSender($domain->getParam('name'), $request->getParam('block_ip_dom'), 'block-ip-dom');
		$wwelement->setBulkSender($domain->getParam('name'), $request->getParam('spam_ip_dom'), 'spam-ip-dom');
		$wwelement->setBulkSender($domain->getParam('name'), $request->getParam('want_ip_dom'), 'want-ip-dom');
		$wwelement->setBulkSender($domain->getParam('name'), $request->getParam('wh_spamc_ip_dom'), 'wh-spamc-ip-dom');

		return true;
	}
}
