<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * Firewall access table
 */

class Default_Model_DbTable_FirewallRule extends Zend_Db_Table_Abstract
{
    protected $_name    = 'external_access';
    
    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
