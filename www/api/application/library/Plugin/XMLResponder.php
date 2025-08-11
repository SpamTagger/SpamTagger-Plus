<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * index page controller
 */

class Plugin_XMLResponder extends Zend_Controller_Plugin_Abstract
{
	public function postDispatch(Zend_Controller_Request_Abstract $request) {

		$response = Zend_Registry::get('response');
		if ($response->hasResponse()) {
			$this->throwResponse($response);
		}
	}

	protected function throwResponse($result) {
		if (Zend_Registry::get('soap')) {
			return;
		}
		$response = Zend_Registry::get('response');
		$this->_response->setHeader('Content-Type', 'text/xml; charset=utf-8')
		->setBody($response->getXMLResponse());
	}

}