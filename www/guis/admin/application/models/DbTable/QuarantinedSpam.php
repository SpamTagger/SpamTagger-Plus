<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Quarantined spam table
 */

class Default_Model_DbTable_QuarantinedSpam extends Zend_Db_Table_Abstract
{
    protected $_name    = 'spam';
    protected $_primary = 'exim_id';

    public function __construct() {
    	$this->_db = Zend_Registry::get('spooldb');
    }

    public function setTableName($name) {
    	$this->_name = $name;
    }

    public function getTableName() {
    	return $this->_name;
    }

}
