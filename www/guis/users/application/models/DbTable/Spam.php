<?php

/**
 * SpamTagger
 *
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @copyright 2025, SpamTagger
 */

/**
 * Spam controller
 */
class Default_Model_DbTable_Spam extends Zend_Db_Table_Abstract
{
    protected $_name    = 'spam';
    protected $_primary = 'exim_id';
    
    public function __construct() {
    	$this->_db = Zend_Registry::get('spooldb');
    }
}
