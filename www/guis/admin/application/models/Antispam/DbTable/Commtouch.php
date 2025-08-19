<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Commtouch internal table
 */

class Default_Model_Antispam_DbTable_Commtouch extends Zend_Db_Table_Abstract
{
    protected $_name    = 'Commtouch';
    protected $_primary = 'set_id';

    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
