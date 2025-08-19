<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Validate a list of email addresses
 */

class Validate_PKIPrivateKey extends Zend_Validate_Abstract
{
    const MSG_PRIVATEKEY = 'invalidPrivateKey';

    protected $_messageTemplates = array(
        self::MSG_PRIVATEKEY => "Not a valid private key"
    );

    public function isValid($value)
    {
        $this->_setValue($value);

        $pki = new Default_Model_PKI();
        $pki->setPrivateKey($value);
        if ($pki->checkPrivateKey()) {
            return true;
        }
        $this->_error(self::MSG_PRIVATEKEY);
        return false;
    }
}