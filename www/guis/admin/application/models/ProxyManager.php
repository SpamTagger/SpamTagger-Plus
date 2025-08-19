<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Proxies settings
 */

class Default_Model_ProxyManager
{
	protected $_httpproxy = '';
	protected $_smtpproxy = '';

	public function load() {
		$config = SpamTagger_Config::getInstance();
		$this->setHttpProxy($config->getOption('HTTPPROXY'));
		$this->setSmtpProxy($config->getOption('SMTPPROXY'));
	}

    public function getHttpProxy() {
    	return $this->_httpproxy;
    }
    public function setHttpProxy($string) {
    	$string = preg_replace('/http:\/\//', '', $string);
    	$this->_httpproxy = $string;
    }
    public function getHttpProxyString() {
    	if ($this->_httpproxy != '') {
            return 'http://'.$this->_httpproxy;
    	}
    	return '';
    }

    public function getSmtpProxy() {
    	return $this->_smtpproxy;
    }
    public function setSmtpProxy($string) {
    	$this->_smtpproxy = $string;
    }

    public function save()
    {
    	return Default_Model_Localhost::sendSoapRequest('Config_saveSTConfigOption', array('HTTPPROXY' => $this->getHttpProxyString(), 'SMTPPROXY' => $this->getSMTPProxy()));
    }

}
