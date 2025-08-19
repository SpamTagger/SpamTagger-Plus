/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

mod_time = false;


$(document).ready(function(){
  $(".timefield").click(function() { mod_time = true;});

  window.setInterval(updateDateTime, 1000);
});

function updateDateTime() {
	if (mod_time) {
		return;
	}
	statusrequest = $.ajax({
		type: "GET",
		  url: baseurl+'/baseconfiguration/getdateandtime',
		  dataType: "html",
		  success: function(msg){
		       data = msg.split(':');
		       $("#date").val(data[0]);
		       $("#hour").val(data[1]);
		       $("#minute").val(data[2]);
		       $("#second").val(data[3]);
	      }
    });
}
