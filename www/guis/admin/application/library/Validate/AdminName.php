<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Validate a list of email addresses
 */

class Validate_AdminName extends Zend_Validate_Abstract
{
    const MSG_ADMINNAME = 'invalidAdminName';

    protected $_messageTemplates = array(
        self::MSG_ADMINNAME => "'%value%' is not a valid user name"
    );

    public function isValid($value)
    {
        $this->_setValue($value);

        if (preg_match('/[^-_@%&.+a-zA-Z0-9]/', $value)) {
        	$this->_error(self::MSG_ADMINNAME);
        	return false;
        }
        return true;
    }
}