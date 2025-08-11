<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * System configuration table
 */

class Default_Model_DbTable_SystemConf extends Zend_Db_Table_Abstract
{
    protected $_name    = 'system_conf';
    
    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
