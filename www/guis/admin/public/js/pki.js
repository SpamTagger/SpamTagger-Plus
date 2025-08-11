/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

function generatePKI(type, length) {
	url = baseurl+"/pki/createkey/t/"+type+"/l/"+length;
	request = $.ajax({
	  	  type: "GET",
	  	  url: url,
	  	  dataType: "html",
		  async: false,
	  	  success: function(msg){
            setupFields(msg);
	      },
	      error: function() {
	      }
	  });
}

function setupFields(msg) {
	obj = jQuery.parseJSON(msg);
	$(".pki_privatekey").val(obj.privateKey);
}
