<?php
/**
 * SpamTagger
 * 
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @copyright 2025, SpamTagger
 */

/**
 * @author jpgrossglauser
 * Class for user table
 */
class Default_Model_DbTable_UserPreference extends Zend_Db_Table_Abstract
{
    /**
     * @see end_Db_Table_Abstract
     */
    protected $_name    = 'user_pref';

    /**
     * @var array
     */
    protected $_dependentTables = array('user');
        
    /**
     * Constructor
     */
    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
