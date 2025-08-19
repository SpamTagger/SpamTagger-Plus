<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * controller for smtp settings
 */

class PkiController extends Zend_Controller_Action
{
    public function init()
    {
    	$layout = Zend_Layout::getMvcInstance();
        $view=$layout->getView();
        $layout->disableLayout();
        $view->addScriptPath(Zend_Registry::get('ajax_script_path'));

    }

    public function indexAction() {

    }

    public function createkeyAction() {

    	$layout = Zend_Layout::getMvcInstance();
        $view=$layout->getView();

        $request = $this->getRequest();
        $params = array('type' => $request->getParam('t'), 'length' =>  $request->getParam('l'));

    	$pki = new Default_Model_PKI();
    	$pki->createKey($params);

    	$key = array('privateKey' => $pki->getPrivateKey(), 'privateKeyNoPEM' => $pki->getPrivateKeyNoPEM(),
    	             'publicKey' => $pki->getPublicKey(), 'publicKeyNoPem' => $pki->getPublicKeyNoPEM());
    	$this->_helper->json($key);
    }

}