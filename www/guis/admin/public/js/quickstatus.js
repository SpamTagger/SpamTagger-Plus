/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

var statusrequest;
var hostreloadtime = 5000;
var graphStatus = new Array();

$(document).ready(function(){
	$("#statusreloadimg").click(function(event){
        loading();
        event.preventDefault();
      });

	$("a.menubutton").click(function(event){
		abortStatus();
		//event.preventDefault();
	});
	loading();
});

function loading() {
	if (replica) {
            $("#statuspanel").html("not running on replica");
		return;
	}

	$("#statuspanel").html(loadinghtml);
	statusrequest = $.ajax({
		  type: "GET",
		  url: quickstatusurl,
		  dataType: "html",
		  timeout: 5000,
		  success: function(msg){
            $("#statuspanel").html(msg);
    	    setTimeout("loading()", statusreload);
          },
          error: function() {
        	$("#statuspanel").html();
            setTimeout("loading()", statusreload)
          }
		});
}

function abortStatus() {
	statusrequest.abort();
	delete statusrequest;
}
