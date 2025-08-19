<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Validate a domain name
 */

class Validate_DomainName extends Zend_Validate_Abstract
{
    const MSG_DOMAINNAME = 'invalidDomainName';

    protected $_messageTemplates = array(
        self::MSG_DOMAINNAME => "'%value%' is not a valid domain name"
    );

    public function isValid($value)
    {
        $this->_setValue($value);

        if ($value == '') {
        	return false;
        }
        if (preg_match('/^[a-z0-9\-_.]+$/', $value)) {
        	return true;
        }
        $this->_error(self::MSG_DOMAINNAME);
        return false;
    }
}