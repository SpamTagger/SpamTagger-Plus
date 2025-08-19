<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Administrator
 */

class Default_Model_InformationalMessage_ServiceRestart extends Default_Model_InformationalMessage
{
	protected $_title = 'Services need to be restarted';
	protected $_description = 'the following services need to be restarted for changes to take effect immediately: ';
	protected $_link = array('controller' => 'monitorstatus', 'action' => 'index');
	protected $_services = array();

	public function check() {
		require_once('SpamTagger/Config.php');
		$config = new SpamTagger_Config();

		$services_to_test = array('exim_stage1', 'exim_stage2', 'exim_stage4', 'mailscanner', 'clamd', 'firewall', 'greylistd', 'apache', 'snmpd');

		foreach ($services_to_test as $service) {
			$restart_file = $config->getOption('VARDIR')."/run/".$service.".rn";
			if (file_exists($restart_file)) {
				array_push($this->_services, $service);
				$this->_toshow = true;
			}
		}
	}

	public function getDescription() {
		$t = Zend_Registry::get('translate');
		$t_services = array();
		foreach ($this->_services as $s) {
			$t_services[] = $t->_('process_'.$s);
		}
		$res = $this->_description." <span class=\"mark\">".implode(', ',$t_services)."</span>";
		return $res;
	}
}
