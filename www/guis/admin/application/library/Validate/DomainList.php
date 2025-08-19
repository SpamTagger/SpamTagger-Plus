<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Validate domain name list
 */

class Validate_DomainList extends Zend_Validate_Abstract
{
    const MSG_DOMAINLIST = 'invalidDomainllist';
    const MSG_BADDOMAIN = 'invalidDomain';

    protected $_messageTemplates = array(
        self::MSG_DOMAINLIST => "'%value%' is not a valid domain list",
        self::MSG_BADDOMAIN => "'%dom%' is not a valid domain"
    );

    public $domain = '';

    protected $_messageVariables = array(
        'dom' => 'domain'
    );

    public function isValid($value)
    {
        $this->_setValue($value);

        require_once('Validate/DomainName.php');
        $validator = new Validate_DomainName();

        $addresses = preg_split('/[,:\s]+/', $value);
        foreach ($addresses as $address) {
          if ($address == '*') {
          	continue;
          }
          if (preg_match('/^\^/', $address)) {
          	continue;
          }
          if (! $validator->isValid($address)) {
          	  $this->domain = $address;
          	  $this->_error(self::MSG_BADDOMAIN);
              return false;
          }
        }
        return true;
    }
}