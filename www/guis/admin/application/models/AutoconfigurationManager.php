<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Mentor Reka
 * @copyright 2025, SpamTagger
 * 
 * Auto-configuration Manager
 */

class Default_Model_AutoconfigurationManager
{
        private $ST_AUTOCONF_TAG_FILE="/spool/spamtagger/st-autoconf";
	protected $_config;
	protected $_autoconfenabled = false;

	public function load() {
		$this->_config = SpamTagger_Config::getInstance();
		$this->setAutoconfenabled(file_exists($this->_config->getOption('VARDIR').$this->ST_AUTOCONF_TAG_FILE));
	}

	public function getAutoconfenabled() {
		return $this->_autoconfenabled;
	}

    	public function setAutoconfenabled($autoconfenabled) {
    		$this->_autoconfenabled = $autoconfenabled;
	}

	public function save()
	{
		return Default_Model_Localhost::sendSoapRequest('Config_autoconfiguration', array('autoconfenabled' => $this->getAutoconfenabled()));
    	}

	public function download()
	{
		return Default_Model_Localhost::sendSoapRequest('Config_autoconfigurationDownload', array('download' => true));
	}

}
