/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

$(document).ready(function(){

	 $("#enable_wantlists").click(function(event){
		 if ($("#enable_wantlists").is(':checked')) {
             $("#wantlist_list").show();
             $(".wantlist_options").show();
		 } else {
        	 $("#wantlist_list").hide();
             $(".wantlist_options").hide();
		 }
	 });

	$("#enable_blocklists").click(function(event){
                 if ($("#enable_blocklists").is(':checked')) {
             $("#blocklist_list").show();
             $(".blocklist_options").show();
                 } else {
                 $("#blocklist_list").hide();
             $(".blocklist_options").hide();
                 }
         });

	 $("#enable_warnlists").click(function(event){
		 if ($("#enable_warnlists").is(':checked')) {
             $("#warnlist_list").show();
		 } else {
             $("#warnlist_list").hide();
		 }
	 });

	 $("#use_bayes").click(function(event){
		 if ($("#use_bayes").is(':checked')) {
	        $("#bayes_autolearn").removeAttr('disabled');
		 } else {
		    $("#bayes_autolearn").attr("disabled", "disabled");
		 }
	 });

	 $("#use_rbls").click(function(event){
		 if ($("#use_rbls").is(':checked')) {
		     $("#rbls_timeout").removeAttr('disabled');
			 $("#iprbls").show();
			 $("#urirbls").show();
		 } else {
			 $("#rbls_timeout").attr("disabled", "disabled");
			 $("#iprbls").hide();
			 $("#urirbls").hide();
		 }
	 });

	 $("#use_dcc").click(function(event){
		 if ($("#use_dcc").is(':checked')) {
		        $("#dcc_timeout").removeAttr('disabled');
		 } else {
			    $("#dcc_timeout").attr("disabled", "disabled");
		 }
	 });

	 $("#use_razor").click(function(event){
		 if ($("#use_razor").is(':checked')) {
		        $("#razor_timeout").removeAttr('disabled');
		 } else {
			    $("#razor_timeout").attr("disabled", "disabled");
		 }
	 });

	 $("#use_pyzor").click(function(event){
		 if ($("#use_pyzor").is(':checked')) {
		        $("#pyzor_timeout").removeAttr('disabled');
		 } else {
			    $("#pyzor_timeout").attr("disabled", "disabled");
		 }
	 });

	 $("#use_spf").click(function(event){
		 if ($("#use_spf").is(':checked')) {
		        $("#spf_timeout").removeAttr('disabled');
		 } else {
			    $("#spf_timeout").attr("disabled", "disabled");
		 }
	 });

	 $("#use_dkim").click(function(event){
		 if ($("#use_dkim").is(':checked')) {
		        $("#dkim_timeout").removeAttr('disabled');
		 } else {
			    $("#dkim_timeout").attr("disabled", "disabled");
		 }
	 });

	 $("#use_domainkeys").click(function(event){
		 if ($("#use_domainkeys").is(':checked')) {
		        $("#domainkeys_timeout").removeAttr('disabled');
		 } else {
			    $("#domainkeys_timeout").attr("disabled", "disabled");
		 }
	 });

	 $(".disabled").attr("disabled", "disabled");
});
