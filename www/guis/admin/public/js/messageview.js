/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

var new_height=700;
var win_width=700;

$(document).ready(function(){
	window.resizeTo(win_width, new_height);
});

var popup_width = 500;
var cpopup_height = 200;

function redimAndForce(msgid, storeid, news) {
	  redim(popup_width, cpopup_height);
	  document.location = baseurl+'/managecontentquarantine/force/id/'+msgid+"/s/"+storeid
		+ '/lang/en/pop/up/n/' + news
}

function redim(width, height) {
	  window.resizeTo(width, height);
	  
	  // workaround for ie7 resizeTo
	  var cp = document.createElement("div");
	  cp.style.position = "absolute";
	  cp.style.width = "0px";
	  cp.style.height = "0px";
	  cp.style.right = "0px";
	  cp.style.bottom = "0px";
	  document.body.appendChild(cp);
	  var current_width = cp.offsetLeft;
	  var current_height = cp.offsetTop;
	  var dw = popup_width - current_width;
	  var dh = popup_height - current_height;
	  document.body.removeChild(cp);  
	  window.resizeBy(dw, dh);
	  // end workaround

	  window.scrollbars.visible = false;
}
