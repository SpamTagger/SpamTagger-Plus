<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Administrator mapper
 */

class Default_Model_FeatureRestrictionMapper
{

    protected $_dbTable;

    public function setDbTable($dbTable)
    {
        if (is_string($dbTable)) {
            $dbTable = new $dbTable();
        }
        if (!$dbTable instanceof Zend_Db_Table_Abstract) {
            throw new Exception('Invalid table data gateway provided');
        }
        $this->_dbTable = $dbTable;
        return $this;
    }

    public function getDbTable()
    {
        if (null === $this->_dbTable) {
            $this->setDbTable('Default_Model_DbTable_FeatureRestriction');
        }
        return $this->_dbTable;
    }

    public function fetchAll($params)
    {
    	$restrictions = array();
    	$query = $this->getDbTable()->select();

    	if (isset($params['target']) && preg_match('/^(administrator|manager|hotline|user)$/', $params['target'])) {
    		$query->where('target_level = ?', $params['target']);
    	}
        $resultSet = $this->getDbTable()->fetchAll($query);
        foreach ($resultSet as $row) {
        	$restrictions[$row['section']][$row['feature']] = array('target' => $row['target_level'], 'restricted' => $row['restricted']);
        }
        return $restrictions;
    }

}