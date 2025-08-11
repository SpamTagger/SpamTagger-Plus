/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

$(document).ready(function(){
	 
	 $("#max_attach_size_enable").click(function(event){
		 if ($("#max_attach_size_enable").is(':checked')) {
			$("#max_attach_size").attr("disabled", "disabled");
			$("#max_attach_size").val('');
		 } else {
		    $("#max_attach_size").removeAttr('disabled');
		 }
	 });
	 
	 $("#max_archive_depth_disable").click(function(event){
		 if ($("#max_archive_depth_disable").is(':checked')) {
			$("#max_archive_depth").attr("disabled", "disabled");
			$("#max_archive_depth").val('');
		 } else {
		    $("#max_archive_depth").removeAttr('disabled');
		 }
	 });
	 
	 $("#expand_tnef").click(function(event){
		 if ($("#expand_tnef").is(':checked')) {
			    $("#deliver_bad_tnef").removeAttr('disabled');
			    $("#usetnefcontent").removeAttr('disabled');
		 } else {
				$("#deliver_bad_tnef").attr("disabled", "disabled");
				$("#usetnefcontent").attr("disabled", "disabled");
		 }
	 });
	 
	 $("#send_notices").click(function(event){
		 if ($("#send_notices").is(':checked')) {
			    $("#notices_to").removeAttr('disabled');
		 } else {
				$("#notices_to").attr("disabled", "disabled");
		 }
	 });
	 
	 $(".disabled").attr("disabled", "disabled");
});
