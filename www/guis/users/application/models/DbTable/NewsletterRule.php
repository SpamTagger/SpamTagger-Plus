<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @copyright 2025, SpamTagger
 */
class Default_Model_DbTable_NewsletterRule extends Zend_Db_Table_Abstract
{
    protected $_name    = 'wwlists';

    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
