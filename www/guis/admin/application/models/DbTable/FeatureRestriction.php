<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Administrator table
 */

class Default_Model_DbTable_FeatureRestriction extends Zend_Db_Table_Abstract
{
    protected $_name    = 'feature_restriction';
    protected $_primary = 'id';

    public function __construct() {
    	$this->_db = Zend_Registry::get('writedb');
    }
}
