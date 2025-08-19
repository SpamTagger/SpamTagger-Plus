<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Validate a list of email addresses
 */

class Validate_MessageID extends Zend_Validate_Abstract
{
    const MSG_MESSAGEID = 'invalidMessageID';

    protected $_messageTemplates = array(
        self::MSG_MESSAGEID => "'%value%' is not a valid message ID"
    );

    public function isValid($value)
    {
        $this->_setValue($value);

        if (preg_match('/^[0-9A-Z]{6}-[0-9A-Z]{6,11}-[0-9A-Z]{2,4}$/i', $value)) {
        	return true;
        }
    }
}
