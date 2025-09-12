<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Set host id
 */

class Default_Model_HostIdManager {
  private $_data = array('host_id' => '');

	public function load() {
		//TODO: implement
	}

  public function setData($what, $value) {
    $this->_data[$what] = $value;
  }
  public function getData($what) {
    if (isset($this->_data[$what])) {
      return $this->_data[$what];
    }
    return '';
  }

  public function save() {
    $this->_data['timeout'] = 200;
    return Default_Model_Localhost::sendSoapRequest('Config_hostid', $this->_data);
  }

}
