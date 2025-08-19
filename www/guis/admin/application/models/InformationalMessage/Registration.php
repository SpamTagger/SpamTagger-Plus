<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Administrator
 */

class Default_Model_InformationalMessage_Registration extends Default_Model_InformationalMessage
{
	protected $_title = 'System is unregistered';
	protected $_description = 'unregistered system has low efficiency';
	protected $_link = array('controller' => 'baseconfiguration', 'action' => 'registration');
	public function check() {
		require_once('SpamTagger/Config.php');
    		$config = new SpamTagger_Config();
    		$registered = $config->getOption('REGISTERED');
		if (!isset($registered) && $registered != "1" && $registered != "2")
    	    		$this->_toshow = true;
	}
}
