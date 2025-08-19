<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * index page controller
 */

class UserController extends Zend_Controller_Action
{

	public function init()
	{
		$this->_helper->layout->disableLayout();
		$this->_helper->viewRenderer->setNoRender(true);
	}

	public function addAction()
	{
		$request = $this->getRequest();
		$api = new Api_Model_UserAPI();
		$api->add($request->getParams());
	}

    public function editAction()
    {
        $request = $this->getRequest();
        $api = new Api_Model_UserAPI();
        $api->edit($request->getParams());
    }

    public function existsAction()
    {
        $request = $this->getRequest();
        $api = new Api_Model_UserAPI();
        $api->exists($request->getParams());
    }

    public function deleteAction()
    {
        $request = $this->getRequest();
        $api = new Api_Model_UserAPI();
        $api->delete($request->getParams());
    }

    public function showAction()
    {
        $request = $this->getRequest();
        $api = new Api_Model_UserAPI();
        $api->show($request->getParams());
    }

    public function listAction()
    {
    	$request = $this->getRequest();
        $api = new Api_Model_UserAPI();
    	$api->userList($request->getParams());
    }

    public function listAddresses()
    {
    	$request = $this->getRequest();
        $api = new Api_Model_UserAPI();
    	$api->listAddresses($request->getParams());
    }
}