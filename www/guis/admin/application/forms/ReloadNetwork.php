<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * Network reload form
 */

class Default_Form_ReloadNetwork extends Zend_Form
{
	
	public function init()
	{
		$this->setMethod('post');
			
		$t = Zend_Registry::get('translate');
		$this->setAttrib('id', 'reloadnetworkform');
		
		$submit = new Zend_Form_Element_Submit('submit', array(
		     'label'    => $t->_('Reload network now'),
		     'id'       => 'reloadnetbutton'));
		$this->addElement($submit);
                $restrictions = Zend_Registry::get('restrictions');
                if ($restrictions->isRestricted('NetworkInterface', 'reloadnetnow')) {
			$submit->setAttrib('disabled', 'disabled');
		}
		
	}

}
