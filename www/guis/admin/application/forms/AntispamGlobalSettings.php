<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Antispam global settings form
 */

class Default_Form_AntispamGlobalSettings extends ZendX_JQuery_Form
{
	protected $_antispam;
	public $_wantlist;
	public $_warnlist;
	//blocklistmr
	public $_blocklist;
    public $_newslist;

	public $_wantlistenabled = 0;
	public $_warnlistenabled = 0;
	public $_blocklistenabled = 0;

	protected $_wantlistform;
	protected $_warnlistfrom;
	protected $_blocklistrom;
    protected $_newslistform;

	public function __construct($as, $wantlist, $warnlist, $blocklist, $newslist) {
		$this->_antispam = $as;
		$this->_wantlist = $wantlist;
		$this->_warnlist = $warnlist;
		$this->_blocklist = $blocklist;
        $this->_newslist = $newslist;
		parent::__construct();
	}


	public function init()
	{
		$t = Zend_Registry::get('translate');
		$layout = Zend_Layout::getMvcInstance();
    	$view=$layout->getView();

		$this->setMethod('post');

		$this->setAttrib('id', 'antispamglobalsettings_form');

         	$maxsize = new Zend_Form_Element_Text('global_max_size', array(
		    'label'    => $t->_('Global max scan size (KB)'). " :",
		    'required' => false,
		    'filters'    => array('StringTrim')));
        	$maxsize->addValidator(new Zend_Validate_Int());
	    	$maxsize->setValue($this->_antispam->getParam('global_max_size'));
		$this->addElement($maxsize);

		require_once('Validate/IpList.php');
		$trustednet = new Zend_Form_Element_Textarea('trusted_ips', array(
		      'label'    =>  $t->_('Trusted IPs/Networks')." :",
                      'title' => $t->_("These IP/ranges are wantlist for the antispam part"),
		      'required'   => false,
		      'rows' => 5,
		      'cols' => 30,
		      'filters'    => array('StringToLower', 'StringTrim')));
	    $trustednet->addValidator(new Validate_IpList());
		$trustednet->setValue($this->_antispam->getParam('trusted_ips'));
		$this->addElement($trustednet);

		$enablewantlists = new Zend_Form_Element_Checkbox('enable_wantlists', array(
	        'label'   => $t->_('Enable access to wantlists'). " :",
                'title' => $t->_("Activate globally that wantlist behavior is becoming available, after global wantlist also become availableActivate globally that wantlist behavior is becoming available, after global wantlist also become available"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
               $enableblocklists = new Zend_Form_Element_Checkbox('enable_blocklists', array(
                 'label'   => $t->_('Enable access to blocklists'). " :",
                'title' => $t->_("Activate globally that blocklist behavior is becoming available, after global blocklist also become availableActivate globally that blocklist behavior is becoming available, after global blocklist also become available"),
             'uncheckedValue' => "0",
                 'checkedValue' => "1"
                       ));

	    if ($this->_antispam->getParam('enable_wantlists')) {
            $enablewantlists->setChecked(true);
            $this->_wantlistenabled = 1;
	    }
	    $this->addElement($enablewantlists);

	    $enablewarnlists = new Zend_Form_Element_Checkbox('enable_warnlists', array(
	        'label'   => $t->_('Enable access to warnlists'). " :",
                'title' => $t->_("Activate globally that warnlist behavior is becoming available, after global warnlist also become availableActivate globally that warnlist behavior is becoming available, after global warnlist also become available"),
            'uncheckedValue' => "0",
	        'checkedValue' => "1"
	              ));
	    if ($this->_antispam->getParam('enable_warnlists')) {
            $enablewarnlists->setChecked(true);
            $this->_warnlistenabled = 1;
	    }
	    $this->addElement($enablewarnlists);

	    $tagmodbypasswantlist = new Zend_Form_Element_Checkbox('tag_mode_bypass_wantlist', array(
            'label'   => $t->_('Ignore wantlist in tag mode'). " :",
            'title' => $t->_("since tag mode get all messages delivered, one may want to ignore the wantlist in this case"),
            'uncheckedValue' => "0",
            'checkedValue' => "1"
                  ));
	if ($this->_antispam->getParam('enable_blocklists')) {
            $enableblocklists->setChecked(true);
            $this->_blocklistenabled = 1;
            }
            $this->addElement($enableblocklists);

        if ($this->_antispam->getParam('tag_mode_bypass_wantlist')) {
            $tagmodbypasswantlist->setChecked(true);
        }
        $this->addElement($tagmodbypasswantlist);




            $wantlistbothfrom = new Zend_Form_Element_Checkbox('wantlist_both_from', array(
            'label'   => $t->_('Apply wantlist on Body-From too'). " :",
            'title' => $t->_("By default wantlists are checked versus SMTP-From. Activating this feature will use wantlist versus Body-From as well. If unsure please leave this option unchecked."),
            'uncheckedValue' => "0",
            'checkedValue' => "1"
                  ));

        if ($this->_antispam->getParam('wantlist_both_from')) {
            $wantlistbothfrom->setChecked(true);
        }
        $this->addElement($wantlistbothfrom);





		$submit = new Zend_Form_Element_Submit('submit', array(
		     'label'    => $t->_('Submit')));
		$this->addElement($submit);

		$this->_wantlistform = new Default_Form_ElementList($this->_wantlist, 'Default_Model_WWElement', 'wantlist_');
		$this->_wantlistform->init();
		$this->_wantlistform->setAddedValues(array('recipient' => '', 'type' => 'want'));
		$this->_wantlistform->addFields($this);

    		$this->_warnlistform = new Default_Form_ElementList($this->_warnlist, 'Default_Model_WWElement', 'warnlist_');
		$this->_warnlistform->init();
		$this->_warnlistform->setAddedValues(array('recipient' => '', 'type' => 'warn'));
		$this->_warnlistform->addFields($this);

		$this->_blocklistform = new Default_Form_ElementList($this->_blocklist, 'Default_Model_WWElement', 'blocklist_');
                $this->_blocklistform->init();
                $this->_blocklistform->setAddedValues(array('recipient' => '', 'type' => 'block'));
                $this->_blocklistform->addFields($this);

		$this->_newslistform = new Default_Form_ElementList($this->_newslist, 'Default_Model_WWElement', 'newslist_');
		$this->_newslistform->init();
		$this->_newslistform->setAddedValues(array('recipient' => '', 'type' => 'wnews'));
		$this->_newslistform->addFields($this);
	}

	public function getWantlistForm() {
		return $this->_wantlistform;
	}

   public function getWarnlistForm() {
		return $this->_warnlistform;
	}

	public function getBlocklistForm() {
                return $this->_blocklistform;
        }

	public function setParams($request, $as) {
		$this->_wantlistform->manageRequest($request);
		$this->_wantlistform->addFields($this);
		$this->_warnlistform->manageRequest($request);
		$this->_warnlistform->addFields($this);
		$this->_blocklistform->manageRequest($request);
                $this->_blocklistform->addFields($this);
		$this->_newslistform->manageRequest($request);
		$this->_newslistform->addFields($this);


		$as->setparam('global_max_size', $request->getParam('global_max_size'));
		$as->setparam('trusted_ips', $request->getParam('trusted_ips'));
		$as->setparam('enable_wantlists', $request->getParam('enable_wantlists'));
		$as->setparam('enable_warnlists', $request->getParam('enable_warnlists'));
		$as->setparam('enable_blocklists', $request->getParam('enable_blocklists'));
	        $as->setparam('tag_mode_bypass_wantlist', $request->getParam('tag_mode_bypass_wantlist'));
	        $as->setparam('wantlist_both_from', $request->getParam('wantlist_both_from'));

		$this->_wantlistenabled = $as->getParam('enable_wantlists');
		$this->_warnlistenabled = $as->getParam('enable_warnlists');
		$this->_blocklistenabled = $as->getParam('enable_blocklists');
	}
}
