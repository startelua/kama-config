
function getHostname()
    local f = io.popen ("/bin/hostname")
    local hostname = f:read("*a") or ""
    f:close()
    hostname =string.gsub(hostname, "\n$", "")
    return hostname
end


FLT_NATS = 1 -- the UAC is behind a NAT , transaction flag
FLB_NATB = 2 -- the UAS is behind a NAT , branch flag
FLT_DIALOG = 4
FLT_FROM_ASTERISK = 10
FLT_FROM_PROVIDER = 11
FLT_FROM_API = 12

------------------------- Request Routing Logic --------------------------
function ksr_request_route()
 -- start duplicate the SIP message here
        KSR.siptrace.sip_trace();
        KSR.setflag(22);

    local request_method = KSR.pv.get("$rm") or "";
    local user_agent = KSR.pv.get("$ua") or "";

    KSR.log("info", " KSR_request_route request, method " .. request_method .. " user_agent " .. user_agent .. "\n");

    -- per request initial checks
    ksr_route_reqinit(user_agent);

    -- OPTIONS processing
    ksr_route_options_process(request_method);

    -- NAT detection
    ksr_route_natdetect();

    -- CANCEL processing
    ksr_route_cancel_process(request_method);

    -- handle requests within SIP dialogs
    ksr_route_withindlg(request_method);

    -- handle retransmissions
    ksr_route_retrans_process();

    -- handle request without to tag
    ksr_route_request_process(request_method);
    return 1;
end


-- Per SIP request initial checks
--------------------------------------------
function ksr_route_reqinit(user_agent)

    -- Max forwards Check
    local max_forward = 10
    local maxfwd_check = KSR.maxfwd.process_maxfwd(max_forward)
    if maxfwd_check < 0 then
        KSR.log("err", "too many hops sending 483")
        KSR.sl.sl_send_reply(483, "Too Many Hops")
        KSR.x.exit()
    end

    -- sanity Check
    local sanity_check = KSR.sanity.sanity_check(1511, 7)
    if sanity_check < 0 then
        KSR.log("err", "received invalid sip packet \n")
        KSR.x.exit()
    end

    KSR.log("info", "initial request check is passed \n")
    return 1
end

-- CANCEL Processing
-- if transaction exists relay CANCEL request, else exit quitely
--------------------------------------------------------------------
function ksr_route_cancel_process(request_method)
    if request_method == "CANCEL" then
        KSR.log("info", "sip cancel request received \n");
        if KSR.tm.t_check_trans() > 0 then
            ksr_route_relay(request_method)
        end
        KSR.x.exit()
    end
    return 1;
end

-- OPTIONS Processing sending keepalive 200
------------------------------------------
function ksr_route_options_process(request_method)
    --  NAT KEEPALIVE SIP OPTION
--[[        if KSR.is_OPTIONS() then
        if KSR.is_myself_ruri() and KSR.corex.has_ruri_user()<0 then
            KSR.sl.sl_send_reply(200, "Keepalive")
            KSR.x.exit()
        end
        end ]]--
    -- NAT
      if request_method == "OPTIONS"
            and KSR.is_myself(KSR.pv.get("$ru"))
            and KSR.pv.is_null("$rU") then
        KSR.log("info", "sending keepalive response 200 \n")
        KSR.sl.sl_send_reply(200, "Keepalive")
        KSR.x.exit()
    end
    return 1
end

--[[--------------------------------------------------------------------------
    Name: ksr_route_request_process()
    Desc: -- route all requests
    if req not INVITE then it will reject the request with 501 , else create the transaction
-----------------------------------------------------------------------------]]
function ksr_route_request_process(request_method)

    --remove pre loaded request route headers
    KSR.hdr.remove("Route");

    if request_method ~= "INVITE" then
        KSR.log("err", "method not allowed, sending 501 \n");
        KSR.sl.sl_send_reply(501, "Method is not implemented");

    else
        KSR.rr.record_route()
        KSR.log("info", "RECORD ROUTE");
        local dest_number = KSR.pv.get("$rU")
        local to_uri = KSR.pv.get("$tu");
        local call_id = KSR.pv.get("$ci")
        local from_number = KSR.pv.get("$fU") or ""
        KSR.setflag(FLT_DIALOG);
        KSR.pv.sets("$avp(dest_number)", dest_number)
        KSR.pv.sets("$avp(to_uri)", to_uri);
        KSR.pv.sets("$avp(from_number)", from_number);
        KSR.pv.sets("$avp(call_id)", call_id);
        if(KSR.isflagset(FLT_FROM_API)) then
            KSR.tm.t_newtran()
            KSR.log("info", "transaction created for call \n");
            KSR.tmx.t_suspend()
            local id_index = KSR.pv.get("$T(id_index)")
            local id_label = KSR.pv.get("$T(id_label)")
            KSR.tmx.t_continue(id_index, id_label, "service_callback")
        end
        if ksr_route_direction() < 0 then
           ksr_route_dispatcher_select()
        end
        ksr_route_relay(request_method)           

        
    end
    KSR.x.exit()
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_retrans_process()
   Desc: -- Retransmission Process
------------------------------------------------------------------------------]]
function ksr_route_retrans_process()
    -- handle retransmissions

    -- check if request is handled by another process
    if KSR.tmx.t_precheck_trans() > 0 then
        KSR.log("info", "retransmission request received \n");
        -- for non-ack and cancel used to send resends the last reply for that transaction
        KSR.tm.t_check_trans()
        KSR.x.exit()
    end

    -- check for acive transactions
    if KSR.tm.t_check_trans() == 0 then
        KSR.log("info", "no active transaction for this request \n");
        KSR.x.exit()
    end
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_withindlg()
   Desc: -- Handle requests within SIP dialogs
------------------------------------------------------------------------------]]

function ksr_route_withindlg(request_method)
    -- return if not a dialog equest , can be checked by missing to tag
    if KSR.siputils.has_totag() < 0 then
        return 1;
    end
    KSR.log("info", "received a request into the dialog, checking loose_route \n");
  

    -- sequential request withing a dialog should take the path determined by record-routing
    if request_method == "BYE" then
        KSR.pv.sets("$dlg_var(bye_rcvd)", "true")
    end

    if request_method == "INVITE" or request_method == "UPDATE" or request_method == "BYE" then
        if KSR.rr.is_direction("downstream") then
            KSR.pv.sets("$avp(is_downstream)", "true");
        else
            local to_uri = KSR.pv.get("$dlg_var(to_uri)") or KSR.pv.get("$avp(to_uri)")
            KSR.pv.sets("$fu", to_uri);
        end
    end

    -- if loose_route just relay , if ACK then Natmanage and relay
    if KSR.rr.loose_route() > 0 then
        KSR.log("info", "in-dialog request,loose_route \n");
        ksr_route_dlguri();
        if request_method == "ACK" then
--[[             KSR.rtpengine.stop_recording()
	     local rtp_option=" metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().." label=pre_call "
         if KSR.rtpengine.rtpengine_manage(rtpengine) > 0 then
            KSR.log("info", "received success reply for rtpengine answer from instance ksr_route_rtp_engine \n")
        else
            KSR.log("err", "received failure reply for rtpengine answer from instance \n")
	    KSR.sl.sl_send_reply("540", "too many rtpengine sessions")
	    KSR.x.drop();
        end
]]--	 
	KSR.log("err","rt_forward stop and start record 212\n") 
	KSR.route("rt_forward_stop")
	KSR.log("err","rt_forward "..KSR.pvx.var_get("exit").."\n") 
       KSR.rtpengine.start_recording()
       ksr_route_natmanage();

        end
        ksr_route_relay(request_method);
        KSR.x.exit()
    end

    KSR.log("info", "in-dialog request,not loose_route \n")
    if request_method == "ACK" then
        -- Relay ACK if it matches with a transaction ... Else ignore and discard
        if KSR.tm.t_check_trans() > 0 then
            -- no loose-route, but stateful ACK; must be an ACK after a 487 or e.g. 404 from upstream server
            KSR.log("info", "in-dialog request,not loose_route with transaction - relaying \n")
            ksr_route_relay(request_method);

        end
        KSR.log("err", "in-dialog request,not loose_route without transaction,exit the  \n")
        KSR.x.exit()
    end
    KSR.log("err", "received invalid sip packet,sending 404 \n");
    KSR.sl.sl_send_reply(404, "Not here");
    KSR.x.exit()
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_dlguri()
   Desc: -- URI update for dialog requests
------------------------------------------------------------------------------]]
function ksr_route_dlguri()
    if not KSR.isdsturiset() then
        KSR.nathelper.handle_ruri_alias()
    end
    return 1
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_relay()
   Desc: adding the reply_route,failure_route,branch_route to request. relay the request.
------------------------------------------------------------------------------]]

function ksr_route_relay(req_method)
    local request_uri = KSR.pv.get("$ru") or ""
    local dest_uri = KSR.pv.get("$du") or ""
    KSR.log("info", "relaying the message with request uri - " .. request_uri .. " destination uri - " .. dest_uri .. "\n");

    local bye_rcvd = KSR.pv.get("$dlg_var(bye_rcvd)") or "false";

    if req_method == "BYE" then
        if KSR.tm.t_is_set("branch_route") < 0 then
            KSR.tm.t_on_branch("ksr_branch_manage");
        end
        KSR.log("info", "sending delete command to rtpengine \n")
	


    elseif req_method == "INVITE" or req_method == "UPDATE" then
        if KSR.tm.t_is_set("branch_route") < 0 then
            KSR.tm.t_on_branch("ksr_branch_manage")
        end

        if KSR.tm.t_is_set("onreply_route") < 0 then
           KSR.tm.t_on_reply("ksr_onreply_manage_rtpengine");
        end

        if KSR.tm.t_is_set("failure_route") < 0 and req_method == "INVITE" then
            KSR.tm.t_on_failure("ksr_failure_manage")
        end

        if bye_rcvd ~= "true" and KSR.textops.has_body_type("application/sdp") > 0 then
            KSR.log("info", "method contains sdp, creating offer to rtpengine \n")
            ksr_route_rtp_engine(req_method);
        end

    elseif req_method == "ACK" then
        if bye_rcvd ~= "true" and KSR.textops.has_body_type("application/sdp") > 0 then
            KSR.log("info", "request contains sdp, sending answer command to rtpengine \n")
            ksr_route_rtp_engine(req_method)
        end
    end


    KSR.tm.t_relay()
    KSR.x.exit()
end


--[[--------------------------------------------------------------------------
   Name: ksr_route_natdetect()
   Desc: caller NAT detection and add contact alias
------------------------------------------------------------------------------]]
function ksr_route_natdetect()
    KSR.force_rport()
    if KSR.nathelper.nat_uac_test(19) > 0 then
        KSR.log("info", "request is behind nat \n")

        if KSR.siputils.is_first_hop() > 0 then
            KSR.log("info", "adding contact alias \n")
            KSR.nathelper.set_contact_alias()
        end
        KSR.setflag(FLT_NATS);
    end
    return 1
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_natmanage()
   Desc: managing the sip-response and sip-request behind the nat
------------------------------------------------------------------------------]]
function ksr_route_natmanage()
    if KSR.siputils.is_request() > 0 then
        if KSR.siputils.has_totag() > 0 then
            if KSR.rr.check_route_param("nat=yes") > 0 then
                KSR.setbflag(FLB_NATB);
            end
        end
    end
    if (not (KSR.isflagset(FLT_NATS) or KSR.isbflagset(FLB_NATB))) then
        return 1;
    end

    if KSR.siputils.is_request() > 0 then
        if not KSR.siputils.has_totag() then
            if KSR.tmx.t_is_branch_route() > 0 then
                KSR.rr.add_rr_param(";nat=yes")
            end
        end
    elseif KSR.siputils.is_reply() > 0 then
        if KSR.isbflagset(FLB_NATB) then
            KSR.nathelper.set_contact_alias()
        end
    end
    return 1;
end

--[[--------------------------------------------------------------------------
   Name: ksr_branch_manage()
   Desc: managing outgoing branch
------------------------------------------------------------------------------]]
function ksr_branch_manage()
    KSR.log("dbg", "new branch [" .. KSR.pv.get("$T_branch_idx") .. "] to " .. KSR.pv.get("$ru") .. "\n");
    ksr_route_natmanage();
    return 1;
end

--[[--------------------------------------------------------------------------
   Name: ksr_onreply_manage()
   Desc: managing incoming response for the request
------------------------------------------------------------------------------]]
function ksr_onreply_manage()
    local response_code = KSR.pv.get("$rs")
    KSR.log("info", "incoming reply with response code " .. tostring(response_code) .. "\n");
    local current_time = KSR.pv.get("$TS")

    local is_downstream = KSR.pv.get("$avp(is_downstream)") or "false";
    if is_downstream == "true" then
        local to_uri = KSR.pv.get("$dlg_var(to_uri)") or KSR.pv.get("$avp(to_uri)")
        KSR.pv.sets("$tu", to_uri);
    end

    if response_code > 100 and response_code < 299 then
        if response_code == 180 or response_code == 183 then
            KSR.log("info", "incoming call_ring_time - " .. current_time)
        elseif response_code == 200 then
            KSR.log("info", "incoming call_answer_time - " .. current_time)
        end
        ksr_route_natmanage();
    end
    return 1;
end

--[[--------------------------------------------------------------------------
   Name: ksr_onreply_manage_answer()
   Desc: managing incoming response for the request and sending answer command to
   rtpengine
------------------------------------------------------------------------------]]

function ksr_onreply_manage_rtpengine()
    local bye_rcvd = KSR.pv.get("$dlg_var(bye_rcvd)") or "false";
    if bye_rcvd ~= "true" and KSR.textops.has_body_type("application/sdp") > 0 then
        KSR.log("info", "response contains sdp, answer to rtpengine \n")
        if (KSR.isflagset(FLT_FROM_ASTERISK)) then
  	   local rtp_option=" metadata=from:pre"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().." label=calleeR "
           rtpengine =rtp_option.."ICE=remove RTP/AVP full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";
-- Провепка возможности форвардинга и записи    
   KSR.log("info", "X-ao recive_forward "..KSR.hdr.is_present('X-ao').."\n")
    if KSR.hdr.is_present('X-ao')>0 then
	KSR.log("info", "X-ao recive_forward on  \n")
        if KSR.hdr.get('X-ao')>0 then
		        KSR.log("info", "723 X_ao >0 recive_forward  "..KSR.hdr.get('X-ao').."\n")
		KSR.route("rt_forward_start")
	end
        -- REMOVE X-HEADER
        KSR.hdr.remove('X-ao')
	KSR.log("err","rt_forward start\n") 
	KSR.route("rt_forward_start")
--        KSR.rtpengine.start_recording()
    end
	KSR.route("rt_forward_start")
-- конец проверки 
	KSR.log("err","rt_forward "..KSR.pvx.var_get("exit").."\n") 
        end
        if (KSR.isflagset(FLT_FROM_PROVIDER)) then
--	  local rtp_option="record-call=yes metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().." label=calleeR "
--	rtp_option..
           rtpengine = "ICE=remove RTP/AVP full-rtcp-attribute direction=priv direction=pub replace-origin replace-session-connection";
        end

        if KSR.rtpengine.rtpengine_manage(rtpengine) > 0 then
            KSR.log("info", "received success reply for rtpengine answer from instance \n")
        else
            KSR.log("err", "received failure reply for rtpengine answer from instance \n")
        end
    end
    ksr_onreply_manage()
    return 1;
end


--[[--------------------------------------------------------------------------
   Name: ksr_onreply_manage_offer()
   Desc: managing incoming response for the request and sending offer command to
   rtpengine
------------------------------------------------------------------------------]]


-- manage  failure response 3xx,4xx,5xx
---------------------------------------------
function ksr_failure_manage()
    local response_code = KSR.pv.get("$T(reply_code)")
    local reply_type = KSR.pv.get("$T(reply_type)")
    local reason_phrase = KSR.pv.get("$T_reply_reason")
    local request_method = KSR.pv.get("$rm");
    KSR.log("err", "failure route: " .. request_method .. " incoming reply received - " ..
            tostring(response_code).." " .. tostring(reply_type) .." ".. tostring(reason_phrase) .. "\n")

    -- send delet command to rtpengine based on callid
    KSR.log("info", "failure route: sending delete command to rtpengine \n")
    KSR.rtpengine.rtpengine_manage("");
--Add del to 
--   KSR.rtpengine.rtpengine_delete("");

    -- check trsansaction state and drop if cancelled
    if KSR.tm.t_is_canceled() == 1 then
        KSR.x.exit()
    end

   if response_code == "401" then
     if KSR.dispatcher.ds_select_next > 0 then
        ksr_route_relay()
     end
   end

    -- KSR.tm.t_set_disable_internal_reply(1)
  --  KSR.sl.send_reply(503, "Service Unavailable")
    KSR.x.exit()
end

function service_callback()
    local dispatch_set = 1
    local routing_policy = 8
    -- selects a destination from addresses set and rewrites the host and port from R-URI.
    if KSR.dispatcher.ds_select_dst(dispatch_set, routing_policy) > 0 then
        KSR.log("info", "request-uri - " .. tostring(KSR.pv.get("$ru")) .. "\n")
        local request_method = KSR.pv.get("$rm") or "";
	KSR.log("info","from "..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
   --	KSR.pv.sets("$td","10.128.0.52")
        ksr_route_relay(request_method);
    else
        KSR.log("err", "dispatcher lookup failed" .. "\n")
        KSR.x.exit()
    end
end


function ksr_route_direction()
    local dispatch_set = 1
    if KSR.dispatcher.ds_is_from_list(dispatch_set) > 0 then
-- ADD  time to start call 
	local start_time = KSR.pv.get("$TF") or ""
        KSR.pv.sets("$avp(start_time)", start_time)

        KSR.log("info","Call from Asterisk " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
        KSR.setflag(FLT_FROM_ASTERISK);
        return 1
    else
       KSR.log("info","Call from Provider " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
       KSR.setflag(FLT_FROM_PROVIDER);
       return -1
    end
end



function ksr_route_dispatcher_select()
--    local routing_policy = 4;
      local routing_policy = 9;	
    local dispatch_set = 1;
        
    if KSR.dispatcher.ds_select_dst(dispatch_set, routing_policy) > 0 then
        KSR.log("info", "request-uri - " .. tostring(KSR.pv.get("$ru")) .. "\n")
        local request_method = KSR.pv.get("$rm") or "";
        local dest_uri = KSR.pv.get("$fu") or ""
	local df = KSR.pv.get("$fd") or ""
	KSR.log("info","Dispatcher from"..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."  dst uri "..dest_uri.."")
	KSR.hdr.append('X-DOMEN-2: '..df..'\r\n')
	KSR.hdr.append('X-kam : ' ..getHostname()..'\r\n')
    else
        KSR.log("err", "dispatcher lookup failed" .. "\n")
        KSR.x.exit()
    end
end


function ksr_route_rtp_engine(req_method)
    if req_method == "INVITE" then 
        if (KSR.isflagset(FLT_FROM_ASTERISK)) then
--	     local rtp_option=" metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().." label=per_call "
--	     local rtp_option="record-call=yes  "
-- rtp_option..
           rtpengine = "ICE=remove RTP/AVP full-rtcp-attribute direction=priv direction=pub replace-origin replace-session-connection";
        end
        if (KSR.isflagset(FLT_FROM_PROVIDER)) then
--    rtp_option..        local rtp_option="record-call=yes metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().." label=calleeR "
           rtpengine ="ICE=remove codec-strip=all codec-offer=PCMA codec-offer=PCMU codec-offer=telephone-event RTP/AVP full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";
        end 
    
       if KSR.rtpengine.rtpengine_manage(rtpengine) > 0 then
            KSR.log("info", "received success reply for rtpengine answer from instance ksr_route_rtp_engine \n")
        else
            KSR.log("err", "received failure reply for rtpengine answer from instance \n")
	    KSR.sl.sl_send_reply("540", "too many rtpengine sessions")
	    KSR.x.drop();
        end
    
--[[
    if (KSR.cfgutils.check_route_exists("sf")) then
	KSR.log("err", "Route ACTIVE \n")
      else
	KSR.log("err", "Route NOT active \n")
    end

    if (KSR.cfgutils.route_if_exists("sf")) then
	KSR.log("err", "Route EXIST ACTIVE \n")
      else
	KSR.log("err", "Route NOT EXIST active \n")
    end
]]--

   end

    if req_method == "ACK" or req_method == "BYE"  then
        KSR.rtpengine.rtpengine_manage()
    end
--[[        if reg_metod =="BYE" then 
        	local to_uri = KSR.pv.get("$tu");
        	local call_id = KSR.pv.get("$ci")
        	local from_number = KSR.pv.get("$fU") or ""
		KSR.log("info","Nats send " ..call_id.." from ".. " to "..to_uri.."\n\r") 
--		KSR.nats.publish("rec_id" , "{'call_id':'"..call_d.."','from':'"..from_number.."','to':'"..to_uri.."}");
    	end ]]-- 
end
--[[---------------- EVENT ]]--


--[[--------------------------------------------------------------------------
   Name: ksr_htable_event(evname)
   Desc: callback for the given htable event-name
------------------------------------------------------------------------------]]

function ksr_htable_event(evname)
    KSR.log("info", "htable module triggered event - " .. evname .. "\n");
    return 1;
end

--[[--------------------------------------------------------------------------
   Name: ksr_dialog_event(evname)
   Desc: get the dispatch domain from the dispatcher list based on policy
------------------------------------------------------------------------------]]

function ksr_dialog_event(evname)
    if (evname == "dialog:start") then
        KSR.log("info", "in dialog event callback with event-name - " .. evname .. "\n")
           	local call_id = KSR.pv.get("$ci")
    		nat_s2=string.format("{'call_id':'%s','from':'%s','to':'%s'}",call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser())
    		KSR.log("info","Nats dialog_s send:"..nat_s2.."\n\r")
    		nat_s=string.format("{'call_id':'%s','from':'%s','to':'%s'}",call_id, KSR.kx.get_fuser())
--, KSR.kx.get_tuser(),KSR.pv.get("$dlg(callid)"))
    		KSR.log("info","Nats dialog_s send:"..nat_s.."\n\r")
		KSR.nats.publish("rec_id_t" , nat_s);
    end
    if (evname == "dialog:end") or (evname == "dialog:failed") then
        KSR.log("info", "in dialog event callback with event-name - " .. evname .. "\n")
--           	local call_id = KSR.pv.get("$ci")
    		nat_s=string.format("{'call_id':'%s','from':'%s','to':'%s'}",call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser())
    		KSR.log("info","Nats dialog_e send:"..nat_s.."\n\r")
		KSR.nats.publish("rec_id_t" , nat_s);
    end
end

--[[--------------------------------------------------------------------------
   Name: ksr_xhttp_event(evname)
   Desc: http request and response handling
------------------------------------------------------------------------------]]

function ksr_xhttp_event(evname)
    local rpc_method = KSR.pv.get("$rm") or ""
    if ((rpc_method == "POST" or rpc_method == "GET")) then
        if KSR.xmlrpc.dispatch_rpc() < 0 then
            KSR.log("err", "error while executing xmlrpc event" .. "\n")
        end
    end
    return 1
end




function ksr_siptrase_event(evname)
--[[     KSR.log("err", " event Name. " ..evname.."  "..KSR.pv.get("$rm").."\n")]]--
     if (evname == "siptrace:msg") then  
     --не трассируем эти методы
       if (KSR.is_method("SPNOI")) then 
         KSR.x.exit()
         --KSR.drop();
        end
    end
end 
--[[
function ksr_xhttp_event(evname)
    local rpc_method = KSR.pv.get("$rm") or ""
    if ((rpc_method == "POST" or rpc_method == "GET")) then
        if KSR.xmlrpc.dispatch_rpc() < 0 then
            KSR.log("err", "error while executing xmlrpc event" .. "\n")
        end
    end
    ksr.log("err","hu  "..KSR.pv.get("$hu").." парсер "..KSR.pv.get("$(hu{s.substr,0,8})") )
    xhttp_prom_root=KSR.pv.get("$(hu{s.substr,0,8})")

    if xhttp_prom_root =="/metrics" then
        ksr.log("info","Called metrics")
    end 
    return 1
end
]]--



function ksr_nats_event(evname)
	KSR.info("===== nats module received event: " .. evname ..", data:" .. KSR.pv.gete('$natsData') .. "\n");
	--ksr.log("info",
	return 1;
end



function ksr_dispatcher_event(evname)
        KSR.log("info","Dispatcher event "..evname.."  rm " ..KSR.pv.gete('$rm') .." Ru "..KSR.pv.gete('$ru') .."\n");
    KSR.nats.publish("asterisk_status" , "{'kama':'"..getHostname().."','sip-gw':'"..KSR.pv.gete('$ru').."','status':'"..evname.."'}");


end


function ksr_topos_event(evname)
        KSR.log("info","!topos event "..evname.." ip "..KSR.pv.gete('$sndto(ip)').."\n");
  if (evname=="topos:msg-outgoing") then
      if (KSR.pv.gete('$sndto(ip)')=="10.128.0.114") then
	        KSR.log("info","topos out drop outgoing ")
	    KSR.x.drop();
	end 
    end

  if (evname=="topos:msg-receiving") then
      if (KSR.pv.gete('$sndto(ip)')=="10.128.0.114") then
	        KSR.log("info","topos out drop resive")
	    KSR.x.drop();
	end 
    end


end



--[[ event_route[xhttp:request] {
    xlog("Got a request!");
    xlog("$ru");
    $var(xhttp_prom_root) = $(hu{s.substr,0,8});
    if ($var(xhttp_prom_root) == "/metrics") {
            xlog("Called metrics");
            prom_dispatch();
            xlog("prom_dispatch() called");
            return;
    } else
        xhttp_reply("200", "OK", "text/html",
                "<html><body>Wrong URL $hu</body></html>");
}
]]--

