<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * SpamTagger configuration fetcher
 */

class SpamTagger_Config
{
	private static $instance;
	private $_configFile = '/etc/spamtagger.conf';

	private $_options = array();

	public static function getInstance() {
		if (empty (self :: $instance)) {
			self :: $instance = new SpamTagger_Config();
		}
		return self :: $instance;
	}

	public function __construct() {
	    $this->getFileConfig();
	}

	private function getFileConfig() {
		$val = array ();
		$ret = array ();

		$lines = file($this->_configFile);
		if (!$lines) { return; }

		foreach ($lines as $line_num => $line) {
			if (preg_match('/^([A-Z0-9]+)\s*=\s*(.*)/', $line, $val)) {
				$this->_options[$val[1]] = $val[2];
			}
		}
	}

	public function getOption($option) {
	    if (isset($this->_options[$option])) {
	        return  $this->_options[$option];
	    }
	    return null;
	}

	public function getUserGUIAvailableLanguages() {
		require_once($this->_options["SRCDIR"]."/www/classes/view/Language.php");
		$lang = Language::getInstance('user');
		return $lang->getLanguages();
	}
}
