<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * Interface login form
 */

class Default_Form_Login extends Zend_Form
{
	public function init()
	{
		$this->setMethod('post');
			
		$t = Zend_Registry::get('translate');
			
		$usernameField = $this->createElement( 'text', 'username', array(
            'label'      => $t->_('Username')." :",
            'required'   => true,
            'filters'    => array('StringTrim'),
		));
#		$usernameField->addValidator(new Zend_Validate_Alnum());

		$usernameField->setDecorators(array(
                              'ViewHelper',
                              'Errors',
		                      array(array('data' => 'HtmlTag'), array('tag' => 'td', 'class' => 'element')),
		                      array('Label', array('tag' => 'td')),
		                      array(array('row' => 'HtmlTag'), array('tag' => 'tr')),
		                 ));
        $usernameField->removeDecorator('Errors');
		$this->addElement($usernameField);

		$passwordField = $this->createElement('password', 'password', array(
             'label'      => $t->_('Password')." :",
             'required'   => true,
             'filters'    => array('StringTrim'),
             'validators' => array(array('validator' => 'StringLength', 'options' => array(0, 100))),
             'allowEmpty' => true,
		));
		$passwordField->setDecorators(array(
                              'ViewHelper',
                              'Errors',
		                      array(array('data' => 'HtmlTag'), array('tag' => 'td', 'class' => 'element')),
		                      array('Label', array('tag' => 'td')),
		                      array(array('row' => 'HtmlTag'), array('tag' => 'tr')),
		                 ));
        $passwordField->removeDecorator('Errors');
		$this->addElement($passwordField);

		$loginButton = $this->createElement('submit', 'submit', array('label'      => 'login'));
		$loginButton->setDecorators(array(
               'ViewHelper',
               array(array('data' => 'HtmlTag'), array('tag' => 'td', 'class' => 'element')),
               array(array('label' => 'HtmlTag'), array('tag' => 'td', 'placement' => 'prepend')),
               array(array('row' => 'HtmlTag'), array('tag' => 'tr')),
           ));
		$this->addElement($loginButton);
		
		$this->setDecorators(array(
               'FormElements',
               array('HtmlTag', array('tag' => 'table')),
               'Form',
           ));

	}

}
