<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

class SoapClass_ProcessusStatus
{
	public $proc1 = 0;
	public $proc2 = 1;

	public function getSoapedValue() {
		return array('proc1' => $this->proc1, 'proc2' => $this->proc2);
	}
}
?>