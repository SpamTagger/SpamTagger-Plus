<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * SMTP servers configuration table
 */

class Default_Model_DbTable_MtaConfig extends Zend_Db_Table_Abstract
{
    protected $_name    = 'mta_config';
    protected $_primary = 'stage';

    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
