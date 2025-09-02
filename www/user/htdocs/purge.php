<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 * 
 * This is the controller for the quarantine purge page
 */

if ($_SERVER["REQUEST_METHOD"] == "HEAD") {
  return 200;
}

require_once("objects.php");
require_once("user/SpamQuarantine.php");
require_once("view/Form.php");
require_once("view/Template.php");
global $user_;

// check variables
if (!isset($user_) || ! $user_ instanceof User) {
  die ("NOUSER");
}
$doit = false;

// check if user has confirmed
if (isset($_GET['doit'])) {
  $doit = true;
  if (gettype($_GET['a']) == string) {
    // get posted values
    $form = new Form('filter', 'GET', $_SERVER['PHP_SELF']);
    $posted = $form->getResult();
    // get quarantine object
    $quarantine = new SpamQuarantine();
    $quarantine->setSettings($posted);
    // do the purge
    if ($quarantine->purge()) {
      $res = $lang_->print_txt_param('PURGEDONE', $quarantine->getSearchAddress());
    } else {
      $res = $lang_->print_txt_param('COULDNOTPURGE', $quarantine->getSearchAddress());
    }
  } else {
    $form = new Form('filter', 'GET', $_SERVER['PHP_SELF']);
    $posted = $form->getResult();
    $addresses = $posted['a'];
    $res = '';
    $quarantine = new SpamQuarantine();
    foreach ($addresses as $a) {
      $posted['a'] = $a;
      if ($user_->hasAddress($a)) {
        $quarantine->setSettings($posted);
        if ($quarantine->purge()) {
          $res .= $lang_->print_txt_param('PURGEDONE', $quarantine->getSearchAddress())."<br/>";
        } else {
          $res .= $lang_->print_txt_param('COULDNOTPURGE', $quarantine->getSearchAddress())."<br/>";
        }
      }
    }
  }
} else {
  if (isset($_GET['a'])) {
    if (gettype($_GET['a']) == 'string') {
      if ($user_->hasAddress($_GET['a'])) {
        $res = $lang_->print_txt_mparam('ASKPURGECONFIRM', array($_GET['days'], $_GET['a']));
      } else {
        $res = $lang_->print_txt('DESTNOTVALID');
	//$doit = false;
      }
    } else {
      $addresses = [];
      foreach ($_GET['a'] as $a) {
        if ($user_->hasAddress($a)) {
          $addresses[] = $a;
        }
      }
      $addstr = implode(", ", $addresses);
      $addstr = preg_replace('/, ([^,]*)$/', "</strong> ".$lang_->print_txt('AND')." <strong>$1", $addstr);
      $res = $lang_->print_txt_mparam('ASKPURGECONFIRM', array($_GET['days'], $addstr));
    }
  }
}

// create view
$template_ = new Template('purge.tmpl');
if ($doit) {
  $template_->setCondition('doit', true);
}

// prepare replacements
$replace = array(
  '__INCLUDE_JS__' => "<script type=\"text/javascript\" charset=\"utf-8\">
                        function confirmation() {
                          window.location.href=\"".$_SERVER['PHP_SELF']."?".$_SERVER['QUERY_STRING']."&doit=1\";
                        }
                       </script>",
  '__MESSAGE__' => $res,
  '__CONFIRM_BUTTON__' => confirm_button($doit)
);

// display page
$template_->output($replace);

/**
 * return the confirm button code if needed
 * @param  $doit      boolean  do we need to really do it or not
 * @return            string   html button string if needed, or "" if not
 */
function confirm_button($doit) {
 $ret = "";
  global $lang_;
  if (!$doit) {
     $ret = "<input type=\"button\" id=\"confirm\" class=\"button\" onclick=\"javascript:confirmation();\" value=\"".$lang_->print_txt('CONFIRM')."\" />";
  }
  return $ret; 
}
?>
