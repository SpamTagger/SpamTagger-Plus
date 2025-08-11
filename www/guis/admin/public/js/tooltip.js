/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

function showToolTip(el, e, fulltxt) {
	var txt = el.children('.tooltiptext').html();
	if (fulltxt && fulltxt != '') {
		txt = fulltxt;
	}

        if (txt == '-' || txt == '') {
          return;
        }
	var xoffset = 5;
	var yoffset = 0;
	
	var position = el.offset();
	if (e) {
		position['left'] = e.pageX;
		position['top'] = e.pageY;
	}
	
	$("#tooltip").html(txt);
	var width = $("#tooltip").outerWidth();
	var height = $("#tooltip").outerHeight();
	
	var fullwidth = $("#container").width();
	var fullheight = $("#container").height();
	
	if (position['left'] + xoffset + width > fullwidth) {
		position['left'] = position['left'] - width - xoffset;
	} else {
		position['left'] += yoffset;
	}
        if (position['left'] < 0) {
                position['left'] = 0;
        }
	if (position['top'] + yoffset + height > fullheight) {
		position['top'] = position['top'] - yoffset - height;
	} else {
		position['top'] += yoffset;
	}
        if (position['top'] < 0) {
                position['top'] = 0;
        }
	
	$("#tooltip").css(position);
	$("#tooltip").show();
}

function hideToolTip() {
	$("#tooltip").hide();
}

function display_hover(el_id, e, show) {
	if (show) {
    	showToolTip($('#'+el_id), e, $('#'+el_id+'_data').html());
	} else {
		hideToolTip();
	}
}
