<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Slave host mapper
 */

class Default_Model_SlaveMapper
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
            $this->setDbTable('Default_Model_DbTable_Slave');
        }
        return $this->_dbTable;
    }

    public function find($id, Default_Model_Slave $replica)
    {
        $result = $this->getDbTable()->find($id);
        if (0 == count($result)) {
            return;
        }
        $replica->setId($id);
        $row = $result->current();
        $replica->setHostname($row->hostname, $row->password);
        $replica->setPassword($row->password);
    }

    public function fetchAll()
    {
        $resultSet = $this->getDbTable()->fetchAll(null, "id ASC");
        $entries   = array();
        foreach ($resultSet as $row) {
            $entry = new Default_Model_Slave();
            $entry->setId($row->id);
            $entry->setHostname($row->hostname, $row->password);
            $entry->setPassword($row->password);
            $entries[] = $entry;
        }
        return $entries;
    }
}
