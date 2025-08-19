<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Administrator
 */

class Default_Model_InformationalMessage
{
	protected $_title = 'Unknown message';
	protected $_description = '';
	protected $_slaves = array();
	protected $_toshow = false;
	protected $_link = array();

	public function getTitle() {
		$t = Zend_Registry::get('translate');
		return $t->_($this->_title);
	}

	public function getDescription() {
		$t = Zend_Registry::get('translate');
		return $t->_($this->_description);
	}

	public function fetchAll() {
		return array();
	}

	public function shouldShow() {
		return $this->_toshow;
	}

	public function getLink() {
                if (isset($this->_link['controller'])) {
		  return $this->_link;
                }
                return null;
	}

	public function getSlavesList() {
		return implode(', ',$this->_slaves);
	}

	public function addSlave($slave) {
           if (!in_array($slave, $this->_slaves)) {
    		array_push($this->_slaves, $slave);
	   }
        }
}
