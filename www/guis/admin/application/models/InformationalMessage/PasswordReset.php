<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Mentor Reka
 * @copyright 2025, SpamTagger
 *
 * Inform when the default password isn't changed
 */

class Default_Model_InformationalMessage_PasswordReset extends Default_Model_InformationalMessage
{
	protected $_title = 'System is not safe';
	protected $_description = null;
	protected $_link = array(); // not used, because custom link
	public function check() {
		require_once('SpamTagger/Config.php');
    		$config = new SpamTagger_Config();
    		$stPwd = $config->getOption('MYSPAMTAGGERPWD');
		if (isset($stPwd) && md5($stPwd) == "cbf0466a9c823ad153ce349411e32407") {
			// We're building custom link when configurator is enabled
			// Check in DB if use_ssl is true and configurator enabled
			$url=".";
			require_once ('helpers/DataManager.php');
			$db_sourceconf = DM_MasterConfig :: getInstance();
			$configurator_enabled=$db_sourceconf->getHash("select * from external_access where service='configurator' AND protocol='TCP' AND port='4242'");
			if ( isset($configurator_enabled['id']) && !empty($configurator_enabled['id'])) {
				$res=$db_sourceconf->getHash("select use_ssl from httpd_config;");
				$protocol=$res['use_ssl']=="true" ? 'https://' : 'http://';
				$url=" (<a href='".$protocol.$_SERVER['SERVER_NAME'].":4242'>Click here to access the wizard</a>).";
			}
			$this->_description="you are using the default SpamTagger password".$url;
    	    		$this->_toshow = true;
		}
	}
}
