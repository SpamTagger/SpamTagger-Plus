<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * Validate a list of email addresses
 */

class Validate_PKICertificate extends Zend_Validate_Abstract
{
    const MSG_CERTIFICATE = 'invalidCertificate';

    protected $_messageTemplates = array(
        self::MSG_CERTIFICATE => "Not a valid certificate"
    );

    public function isValid($value)
    {
        $this->_setValue($value);
        
        $pki = new Default_Model_PKI();
        $pki->setCertificate($value);
        if ($pki->checkCertificate()) {
            return true;
        }
        $this->_error(self::MSG_CERTIFICATE);
        return false;
    }
}