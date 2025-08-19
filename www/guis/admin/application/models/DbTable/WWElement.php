<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * White/Warn lists table
 */

class Default_Model_DbTable_WWElement extends Zend_Db_Table_Abstract
{
    protected $_name    = 'wwlists';

    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
