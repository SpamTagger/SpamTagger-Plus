<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * System configuration mapper
 */

class Default_Model_SystemConfMapper
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
            $this->setDbTable('Default_Model_DbTable_SystemConf');
        }
        return $this->_dbTable;
    }
    
    public function find($id, Default_Model_SystemConf $conf)
    {
        $result = $this->getDbTable()->find($id);
        if (0 == count($result)) {
            return;
        }
        $row = $result->current();
        
        $conf->setId($id);
        foreach ($conf->getAvailableParams() as $key) {
        	$conf->setParam($key, $row->$key);
        }
    }
    
    public function save(Default_Model_SystemConf $conf) {
       $data = $conf->getParamArray();
       $res = '';
       if (null === ($id = $conf->getId())) {
            unset($data['id']);
            $res = $this->getDbTable()->insert($data);
        } else {
            $res = $this->getDbTable()->update($data, array('id = ?' => $id));
        }
        return $res;
    }
    
}