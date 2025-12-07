<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Domain filtering settings form
 */

class Default_Form_DomainFiltering extends Zend_Form
{
	protected $_domain;
	protected $_panelname = 'filtering';

        public $_wantlist;
        public $_warnlist;
	public $_blocklist;
        public $_newslist;

        public $_wantlistenabled = 0;
        public $_warnlistenabled = 0;
	public $_blocklistenabled = 0;

	public function __construct($domain, $wantlist, $warnlist, $blocklist, $newslist)
	{
	    $this->_domain = $domain;
            $this->_wantlist = $wantlist;
            $this->_warnlist = $warnlist;
	    $this->_blocklist = $blocklist;
            $this->_newslist = $newslist;
	    parent::__construct();
	}


	public function init()
	{
		$this->setMethod('post');

		$t = Zend_Registry::get('translate');

		$this->setAttrib('id', 'domain_form');
	    $panellist = new Zend_Form_Element_Select('domainpanel', array(
            'required'   => false,
            'filters'    => array('StringTrim')));
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

		$useantispam = new Zend_Form_Element_Checkbox('spamwall', array(
	        'label'   => $t->_('Enable advanced antispam controls'). " :",
                'title' => $t->_("Enable/Disable antispam part of SpamTagger"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('spamwall')) {
            $useantispam->setChecked(true);
	    }
	    $this->addElement($useantispam);

	    $usecontent = new Zend_Form_Element_Checkbox('contentwall', array(
	        'label'   => $t->_('Enable dangerous content controls'). " :",
                'title' => $t->_("Enable / disable antivirus part of SpamTagger"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('contentwall')) {
            $usecontent->setChecked(true);
	    }
	    $this->addElement($usecontent);

	    $greylist = new Zend_Form_Element_Checkbox('greylist', array(
	        'label'   => $t->_('Enable greylisting'). " :",
                'title' => $t->_("Enable/Disable greylisting (http://www.greylisting.org/)"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getParam('greylist')) {
            $greylist->setChecked(true);
	    }
	    $this->addElement($greylist);

	    $antispoof = new Zend_Form_Element_Checkbox('prevent_spoof', array(
            'label'   => $t->_('Enable antispoof'). " :",
            'title' => $t->_("Rejects messages from the domain you are configuring sent from an IP which is not authorized. If you need to add hosts to the list of allowed senders for your domain, please consider using SPF"),
            'uncheckedValue' => "0",
            'checkedValue' => "1"
                  ));
        if ($this->_domain->getPref('prevent_spoof')) {
            $antispoof->setChecked(true);
        }
        $this->addElement($antispoof);

	$reject_capital_domain = new Zend_Form_Element_Checkbox('reject_capital_domain', array(
            'label'   => $t->_('Reject domains containing capital letters'). " :",
            'title' => $t->_("Forbidss the use of capital letters in the sender s domain name."),
            'uncheckedValue' => "0",
            'checkedValue' => "1"
                  ));
        if ($this->_domain->getPref('reject_capital_domain')) {
            $reject_capital_domain->setChecked(true);
        }
	$this->addElement($reject_capital_domain);

        $require_incoming_tls = new Zend_Form_Element_Checkbox('require_incoming_tls', array(
	        'label'   => $t->_('Reject unencrypted SMTP sessions to this domain'). " :",
                'title' => $t->_("Refuse all unencrypted connection with other MTA"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('require_incoming_tls')) {
            $require_incoming_tls->setChecked(true);
	    }
	    $this->addElement($require_incoming_tls);

	    $enablewantlist = new Zend_Form_Element_Checkbox('enable_wantlists', array(
	        'label'   => $t->_('Enable wantlists'). " :",
                'title' => $t->_("Enable the use of wantlist /!\ (http://spamtagger.org/antispam/documentations/wantlist.html) must be enabled in Configuration > Anti-Spam first"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('enable_wantlists')) {
                $enablewantlist->setChecked(true);
                $this->_wantlistenabled = 1;
	    }
	    $this->addElement($enablewantlist);

	    $enableblocklist = new Zend_Form_Element_Checkbox('enable_blocklists', array(
                'label'   => $t->_('Enable blocklists'). " :",
                'title' => $t->_("Enable the blocklist feature"),
            'uncheckedValue' => "0",
                'checkedValue' => "1"
                      ));
            if ($this->_domain->getPref('enable_blocklists')) {
                $enableblocklist->setChecked(true);
                $this->_blocklistenabled = 1;
            }
            $this->addElement($enableblocklist);

	    $enablewarnlist = new Zend_Form_Element_Checkbox('enable_warnlists', array(
	        'label'   => $t->_('Enable warnlists'). " :",
                'title' => $t->_("Enable / disable the use of warnlist. This list alert the user when a mail comes from sender from the list."),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('enable_warnlists')) {
                $enablewarnlist->setChecked(true);
                $this->_warnlistenabled = 1;
	    }
	    $this->addElement($enablewarnlist);

	    $warnwwhit = new Zend_Form_Element_Checkbox('notice_wwlists_hit', array(
	        'label'   => $t->_('Warn admin on want/warnlist hit'). " :",
                'title' => $t->_("Alert the administrator for every hit in want / warnlist"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_domain->getPref('notice_wwlists_hit')) {
            $warnwwhit->setChecked(true);
	    }
	    $this->addElement($warnwwhit);

	    ### newsl
	    $allowNewsletters = new Zend_Form_Element_Checkbox('allow_newsletters', array(
	        'label'   =>  $t->_('Allow newsletters by default'). " :",
                'title' => $t->_("By default, the newsletters are delivered"),
	        'uncheckedValue' => "0",
	        'checkedValue' => "1"));

	    if ($this->_domain->getPref('allow_newsletters')) {
	        $allowNewsletters->setChecked(true);
	    }

            $this->addElement($allowNewsletters);

            $this->_wantlistform = new Default_Form_ElementList($this->_wantlist, 'Default_Model_WWElement', 'wantlist_');
                $this->_wantlistform->init();
                $this->_wantlistform->setAddedValues(array('recipient' => '@'.$this->_domain->getParam('name'), 'type' => 'want'));
                $this->_wantlistform->addFields($this);

	    $this->_blocklistform = new Default_Form_ElementList($this->_blocklist, 'Default_Model_WWElement', 'blocklist_');
                $this->_blocklistform->init();
                $this->_blocklistform->setAddedValues(array('recipient' => '@'.$this->_domain->getParam('name'), 'type' => 'block'));
                $this->_blocklistform->addFields($this);

            $this->_warnlistform = new Default_Form_ElementList($this->_warnlist, 'Default_Model_WWElement', 'warnlist_');
                $this->_warnlistform->init();
                $this->_warnlistform->setAddedValues(array('recipient' => '@'.$this->_domain->getParam('name'), 'type' => 'warn'));
                $this->_warnlistform->addFields($this);

            $this->_newslistform = new Default_Form_ElementList($this->_newslist, 'Default_Model_WWElement', 'newslist_');
                $this->_newslistform->init();
                $this->_newslistform->setAddedValues(array('recipient' => '@'.$this->_domain->getParam('name'), 'type' => 'wnews'));
                $this->_newslistform->addFields($this);

		$submit = new Zend_Form_Element_Submit('submit', array(
		     'label'    => $t->_('Submit')));
		$this->addElement($submit);
	}

   public function setParams($request, $domain) {
        ### newsl
    	foreach (array('spamwall', 'contentwall', 'enable_wantlists', 'enable_warnlists', 'enable_blocklists', 'notice_wwlists_hit' , 'allow_newsletters') as $p) {
    	    $domain->setPref($p, $request->getParam($p));
    	}

        $this->_wantlistform->manageRequest($request);
        $this->_wantlistform->addFields($this);
        $this->_warnlistform->manageRequest($request);
        $this->_warnlistform->addFields($this);
        $this->_blocklistform->manageRequest($request);
        $this->_blocklistform->addFields($this);
        $this->_newslistform->manageRequest($request);
        $this->_newslistform->addFields($this);

    	$domain->setPref('viruswall', $domain->getPref('contentwall'));
    	$domain->setParam('greylist', $request->getParam('greylist'));
	$domain->setPref('prevent_spoof', $request->getParam('prevent_spoof'));
	$domain->setPref('reject_capital_domain', $request->getParam('reject_capital_domain'));
        $domain->setPref('require_incoming_tls', $request->getParam('require_incoming_tls'));

        ### newsl
        $domain->setPref('allow_newsletters', $request->getParam('allow_newsletters'));

        $this->_wantlistenabled = $domain->getPref('enable_wantlists');
        $this->_warnlistenabled = $domain->getPref('enable_warnlists');
        $this->_blocklistenabled = $domain->getPref('enable_blocklists');

        return true;
     }

	public function wwlistsEnabled() {
		$antispam = new Default_Model_AntispamConfig();
		$antispam->find(1);
		$ret = array();

		if ( $antispam->getParam('enable_wantlists') ) {
			$ret[] = 'wantlist';
		}
		if ($antispam->getParam('enable_warnlists') ) {
			$ret[] = 'warnlist';
		}
		if ($antispam->getParam('enable_blocklists') ) {
			$ret[] = 'blocklist';
		}
		return $ret;
	}

}
