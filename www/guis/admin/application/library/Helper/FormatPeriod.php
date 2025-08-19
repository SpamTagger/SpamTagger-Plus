<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * Setup base view variables
 */

class SpamTagger_View_Helper_FormatPeriod extends Zend_View_Helper_Abstract
{

	protected $_params = array(
	   'periods' => array ('s' => array('second', 'seconds'),
                         'm' => array('minute', 'minutes'),
                         'h' => array('hour', 'hours'),
                         'd' => array('day', 'days'),
                         'w' => array('week', 'weeks'))

	);

	public function formatPeriod($period = '', $params = array())
	{
		$t = Zend_Registry::get('translate');

		foreach ($params as $k => $v) {
			$this->_params[$k] = $v;
		}

		$string = $period;
		foreach ($this->_params['periods'] as $p => $v) {
			if (preg_match('/(\d+)'.$p.'/', $period, $matches)) {
			  $name = $v[0];
			  if ($matches[1] > 1) {
			  	$name = $v[1];
			  }
			  $string = preg_replace('/'.$p.'/', ' '.$t->_($name), $string);
			}
		}
		return $string;
	}
}
