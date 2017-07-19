﻿<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - <#menu5_6_3#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<style>
.Bar_container{
	width:85%;
	height:21px;
	border:1px inset #999;
	margin:0 auto;
	margin-top:20px \9;
	background-color:#FFFFFF;
	z-index:100;
}
#proceeding_img_text{
	position:absolute; 
	z-index:101; 
	font-size:11px; color:#000000; 
	line-height:21px;
	width: 83%;
}
#proceeding_img{
 	height:21px;
	background:#C0D1D3 url(/images/proceeding_img.gif);
}

.button_helplink{
	font-weight: bolder;
	text-shadow: 1px 1px 0px black;
	text-align: center;
	vertical-align: middle;
  background: transparent url(/images/New_ui/contentbt_normal.png) no-repeat scroll center top;
  _background: transparent url(/images/New_ui/contentbt_normal_ie6.png) no-repeat scroll center top;
  border:0;
  color: #FFFFFF;
	height:33px;
	width:122px;
	font-family:Verdana;
	font-size:12px;
  overflow:visible;
	cursor:pointer;
	outline: none; /* for Firefox */
 	hlbr:expression(this.onFocus=this.blur()); /* for IE */
 	white-space:normal;
}
.button_helplink:hover{
	font-weight: bolder;
	background:url(/images/New_ui/contentbt_over.png) no-repeat scroll center top;
	height:33px;
 	width:122px;
	cursor:pointer;
	outline: none; /* for Firefox */
 	hlbr:expression(this.onFocus=this.blur()); /* for IE */
}
</style>

<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script>
var webs_state_update = '<% nvram_get("webs_state_update"); %>';
var webs_state_upgrade = '<% nvram_get("webs_state_upgrade"); %>';
var webs_state_error = '<% nvram_get("webs_state_error"); %>';
var webs_state_info = '<% nvram_get("webs_state_info"); %>';
var firmver_info = "<% nvram_get("firmver"); %>.<% nvram_get("buildno"); %>_<% nvram_get("extendno"); %>";

var varload = 0;
var helplink = "";
var dpi_engine_status = <%bwdpi_engine_status();%>;
function initial(){
	show_menu();
	document.getElementById("firmver_word").innerHTML = firmver_info;
	if(bwdpi_support){
		if(dpi_engine_status.DpiEngine == 1)
			document.getElementById("sig_ver_field").style.display="";
		else
			document.getElementById("sig_ver_field").style.display="none";
			
		var sig_ver = '<% nvram_get("bwdpi_sig_ver"); %>';
		if(sig_ver == "")
			document.getElementById("sig_ver_word").innerHTML = "1.008";
		else
			document.getElementById("sig_ver_word").innerHTML = sig_ver;
	}

	if(!live_update_support || !HTTPS_support){
		document.getElementById("update").style.display = "none";
		document.getElementById("linkpage_div").style.display = "";
		document.getElementById("linkpage").style.display = "";
		helplink = get_helplink();
		document.getElementById("linkpage").href = helplink;
	} 
	else{
		document.getElementById("update").style.display = "";
		document.getElementById("linkpage_div").style.display = "none";
		if('<% nvram_get("webs_state_update"); %>' != '')
			detect_firmware("initial");
	}

	if(based_modelid == "RT-AC68R"){	//MODELDEP	//id: asus_link is in string tag #FW_desc0#
		document.getElementById("asus_link").href = "http://www.asus.com/us/supportonly/RT-AC68R/";
		document.getElementById("asus_link").innerHTML = "http://www.asus.com/us/supportonly/RT-AC68R/";
	}
	
	if(based_modelid == "RT-AC68A"){	//MODELDEP : Spec special fine tune
		document.getElementById("fw_note2").style.display = "none";
		document.getElementById("fw_note3").style.display = "none";
		inputCtrl(document.form.file, 0);
		inputCtrl(document.form.upload, 0);
	}
	else{
		inputCtrl(document.form.file, 1);
		inputCtrl(document.form.upload, 1);
	}
}

var exist_firmver="<% nvram_get("firmver"); %>";
var dead = 0;
function detect_firmware(flag){
	$.ajax({
		url: '/detect_firmware.asp',
		dataType: 'script',
		error: function(xhr){
			dead++;
			if(dead < 30)
				setTimeout("detect_firmware();", 1000);
			else{
					$("#update").show();
  				document.getElementById('update_scan').style.display="none";
  				document.getElementById('update_states').innerHTML="<#connect_failed#>";  				
			}
		},

		success: function(){
  			if(webs_state_update==0){
					setTimeout("detect_firmware();", 1000);
  			}
  			else{	// got wlan_update.zip
				if(webs_state_error == "1"){	//1:wget fail 
					$("#update").show();
					document.getElementById('update_scan').style.display="none";
					if(flag == "initial")
						document.getElementById('update_states').style.display="none";
					else
						document.getElementById('update_states').innerHTML="<#connect_failed#>";
				}
				else if(webs_state_error == "3"){	//3: FW check/RSA check fail
					$("#update").show();
					document.getElementById('update_scan').style.display="none";
					document.getElementById('update_states').innerHTML="<#FIRM_fail_desc#><br><#FW_desc1#>";

				}
				else{
					$("#update").show();
					if(isNewFW(webs_state_info)){
						document.getElementById('update_scan').style.display="none";
						document.getElementById('update_states').style.display="none";
						if(confirm("<#exist_new#>\n\n<#Main_alert_proceeding_desc5#>")){
							document.start_update.action_mode.value="apply";
							document.start_update.action_script.value="start_webs_upgrade";
							document.start_update.submit();
							return;
						}      								
					}
					else{
						document.getElementById('update_scan').style.display="none";
						if(flag == "initial")
							document.getElementById('update_states').style.display="none";
						else{
							document.getElementById('update_states').style.display="";
							document.getElementById('update_states').innerHTML="<#is_latest#>";
						}
					}
				}
			}
		}
	});
}

function detect_update(){
	if(sw_mode != 3 && document.getElementById("connect_status").className == "connectstatusoff"){
		document.getElementById('update_scan').style.display="none";		
		document.getElementById('update_states').innerHTML="<#connect_failed#>";
		document.getElementById('update_states').style.display="";
		return false;		
	}
	else{
		$("#update").hide();
		document.start_update.action_mode.value="apply";
		document.start_update.action_script.value="start_webs_update";  	
		document.getElementById('update_states').innerHTML="<#check_proceeding#>";
		document.getElementById('update_scan').style.display="";
		document.start_update.submit();					
	}
}

var dead = 0;
function detect_httpd(){
	$.ajax({
		url: '/httpd_check.xml',
		dataType: 'xml',
		timeout: 1500,
		error: function(xhr){
			if(dead > 5){
				document.getElementById('loading_block1').style.display = "none";
				document.getElementById('loading_block2').style.display = "none";
				document.getElementById('loading_block3').style.display = "";
				document.getElementById('loading_block3').innerHTML = "<div><#Firm_reboot_manually#></div>";
			}
			else{
				dead++;
			}

			setTimeout("detect_httpd();", 1000);
		},

		success: function(){
			location.href = "index.asp";
		}
	});
}

var rebooting = 0;
function isDownloading(){
	$.ajax({
    		url: '/detect_firmware.asp',
    		dataType: 'script',
				timeout: 1500,
    		error: function(xhr){
					
					rebooting++;
					if(rebooting < 30){
							setTimeout("isDownloading();", 1000);
					}
					else{							
							document.getElementById("drword").innerHTML = "<#connect_failed#>";
							return false;
					}
						
    		},
    		success: function(){
					if(webs_state_upgrade == 0){				
    				setTimeout("isDownloading();", 1000);
					}
					else{ 	// webs_upgrade.sh is done
						
						if(webs_state_error == 1){
								document.getElementById("drword").innerHTML = "<#connect_failed#>";
								return false;
						}
						else if(webs_state_error == 2){
								document.getElementById("drword").innerHTML = "Memory space is NOT enough to upgrade on internet. Please wait for rebooting.<br><#FW_desc1#>";	/* untranslated */ //Untranslated.fw_size_higher_mem
								return false;						
						}
						else if(webs_state_error == 3){
								document.getElementById("drword").innerHTML = "<#FIRM_fail_desc#><br><#FW_desc1#>";
								return false;												
						}
						else{		// start upgrading
								document.getElementById("hiddenMask").style.visibility = "hidden";
								showLoadingBar(270);
								setTimeout("detect_httpd();", 272000);
								return false;
						}
						
					}
  			}
  		});
}

function startDownloading(){
	disableCheckChangedStatus();			
	dr_advise();
	document.getElementById("drword").innerHTML = "&nbsp;&nbsp;&nbsp;<#fw_downloading#>...";
	isDownloading();
}

function check_zip(obj){
	var reg = new RegExp("^.*.(zip|ZIP|rar|RAR|7z|7Z)$", "gi");
	if(reg.test(obj.value)){
			alert("<#FW_note_unzip#>");
			obj.focus();
			obj.select();
			return false;
	}
	else
			return true;		
}

function submitForm(){
	if(!check_zip(document.form.file))
			return;
	else
		onSubmitCtrlOnly(document.form.upload, 'Upload1');	
}

function sig_version_check(){
	$("#sig_check").hide();
	$("#sig_status").show();
	document.sig_update.submit();
	$("#sig_status").html("Signature checking ...");
	setTimeout("sig_check_status();", 12000);
}

function sig_check_status(){
	$.ajax({
    	url: '/detect_firmware.asp',
    	dataType: 'script',
		timeout: 3000,
    	error: function(xhr){					
			setTimeout("sig_check_status();", 1000);				
    	},
    	success: function(){			
			$("#sig_status").show();
			if(sig_state_flag == 0){		// no need upgrade
				$("#sig_status").html("Signature is up to date");
				$("#sig_check").show();
			}
			else if(sig_state_flag == 1){
				if(sig_state_error != 0){		// update error
					$("#sig_status").html("Signature update failed");
					$("#sig_check").show();					
				}
				else{
					if(sig_state_upgrade == 1){		//update complete
						$("#sig_status").html("Signature update completely");
						$("#sig_ver").html(sig_ver);
						$("#sig_check").show();
					}
					else{		//updating
						$("#sig_status").html("Signature is updating");
						setTimeout("sig_check_status();", 1000);
					}				
				}			
			}
  		}
  	});
}
</script>
</head>
<body onload="initial();">

<div id="TopBanner"></div>

<div id="LoadingBar" class="popup_bar_bg">
<table cellpadding="5" cellspacing="0" id="loadingBarBlock" class="loadingBarBlock" align="center">
	<tr>
		<td height="80">
		<div id="loading_block1" class="Bar_container">
			<span id="proceeding_img_text"></span>
			<div id="proceeding_img"></div>
		</div>
		<div id="loading_block2" style="margin:5px auto; width:85%;"><#FIRM_ok_desc#><br><#Main_alert_proceeding_desc5#></div>
		<div id="loading_block3" style="margin:5px auto;width:85%; font-size:12pt;"></div>
		</td>
	</tr>
</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>
<div id="Loading" class="popup_bg"></div><!--for uniform show, useless but have exist-->

<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center" style="height:100px;">
		<tr>
		<td>
			<div class="drword" id="drword" style="">&nbsp;&nbsp;&nbsp;&nbsp;<#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...</div>
		</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form method="post" action="upgrade.cgi" name="form" target="hidden_frame" enctype="multipart/form-data">
<input type="hidden" name="current_page" value="Advanced_FirmwareUpgrade_Content.asp">
<input type="hidden" name="next_page" value="">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">

<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="17">&nbsp;</td>

		<td valign="top" width="202">
		<div id="mainMenu"></div>
		<div id="subMenu"></div>
		</td>

    <td valign="top">
	<div id="tabMenu" class="submenuBlock"></div>
		<!--===================================Beginning of Main Content===========================================-->
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
	<tr>
		<td align="left" valign="top" >

		<table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle" id="FormTitle">
		<tbody>
		<tr>
		  <td bgcolor="#4D595D" valign="top"  >
		  <div>&nbsp;</div>
		  <div class="formfonttitle"><#menu5_6#> - <#menu5_6_3#></div>
		  <div style="margin-left:5px;margin-top:10px;margin-bottom:10px"><img src="/images/New_ui/export/line_export.png"></div>
		  <div class="formfontdesc"><strong><#FW_note#></strong>
				<ol>
					<li><#FW_n0#></li>
					<li><#FW_n1#></li>
					<li id="fw_note2"><#FW_n2#></li>
					<li id="fw_note3"><#FW_desc0#></li>
				</ol>
		  </div>
		  <br>

		<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable">
			<tr>
				<th><#FW_item1#></th>
				<td><#Web_Title2#></td>
			</tr>
<!--###HTML_PREP_START###-->
<!--###HTML_PREP_ELSE###-->
<!--
[DSL-N55U][DSL-N55U-B]
{ADSL firmware version}
			<tr>
				<th><#adsl_fw_ver_itemname#></th>
				<td><input type="text" class="input_15_table" value="<% nvram_dump("adsl/tc_fw_ver_short.txt",""); %>" readonly="1" autocorrect="off" autocapitalize="off"></td>
			</tr>
			<tr>
				<th>RAS</th>
				<td><input type="text" class="input_20_table" value="<% nvram_dump("adsl/tc_ras_ver.txt",""); %>" readonly="1" autocorrect="off" autocapitalize="off"></td>
			</tr>
[DSL-AC68U]
                        <tr>
                                <th>DSL <#FW_item2#></th>
                                <td><% nvram_get("dsllog_fwver"); %></td>
                        </tr>
                        <tr>
                                <th><#adsl_fw_ver_itemname#></th>
                                <td><% nvram_get("dsllog_drvver"); %></td>
                        </tr>
-->

<!--###HTML_PREP_END###-->
			<tr id="sig_ver_field" style="display:none">
				<th>Signature Version</th>
				<td >
					<div id="sig_ver_word" style="padding-top:5px;"></div>
					<div>
						<div id="sig_check" class="button_helplink" style="margin-left:200px;margin-top:-25px;" onclick="sig_version_check();"><a target="_blank"><div style="padding-top:5px;"><#liveupdate#></div></a></div>
						<div>
							<span id="sig_status" style="display:none"></span>
						</div>
					</div>
				</td>
			</tr>
			<tr>
				<th><#FW_item2#></th>
				<td>
						<div id="firmver_word" style="padding-top:5px;"></div>						
						<div>
							<input type="button" id="update" name="update" class="button_gen" style="display:none;margin-left:200px;margin-top:-25px;" onclick="detect_update();" value="<#liveupdate#>">
							<div id="linkpage_div" class="button_helplink" style="margin-left:200px;margin-top:-25px;display:none;"><a id="linkpage" target="_blank"><div style="padding-top:5px;"><#liveupdate#></div></a></div>
							<div id="check_states">
								<span id="update_states"></span>
								<img id="update_scan" style="display:none;" src="images/InternetScan.gif" />
							</div>
						</div>	
				</td>
			</tr>
			<tr style="display:none;">
				<th><#FW_item5#></th>
				<td><input type="file" name="file" class="input" style="color:#FFCC00;*color:#000;width: 300px;"></td>
			</tr>
			<tr align="center" style="display:none;">
			  <td colspan="2"><input type="button" name="upload" class="button_gen" onclick="submitForm()" value="<#CTL_upload#>" /></td>
			</tr>			
		</table>
			  </td>
              </tr>
            </tbody>
            </table>
		  </td>
        </tr>
      </table>
		<!--===================================Ending of Main Content===========================================-->
	</td>

    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>

<div id="footer"></div>
</form>

<form method="post" name="start_update" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_FirmwareUpgrade_Content.asp">
<input type="hidden" name="next_page" value="Advanced_FirmwareUpgrade_Content.asp">
<input type="hidden" name="flag" value="liveUpdate">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="">
</form>
<form method="post" name="sig_update" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_FirmwareUpgrade_Content.asp">
<input type="hidden" name="next_page" value="Advanced_FirmwareUpgrade_Content.asp">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="start_sig_check">
<input type="hidden" name="action_wait" value="">
</form>
</body>
</html>
