
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
FLB_BRIDGE =5 
FLB_RTPWS = 6
FLT_TO_WS =9
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
    local protocol = KSR.pv.get("$pr")
    KSR.log("info", " KSR_request_route request, method " .. request_method .. " user_agent " .. user_agent .." proto "..protocol.."\n");

    -- per request initial checks
    ksr_route_reqinit();

    -- OPTIONS processing
    ksr_route_options_process(request_method);

    -- NAT detection
    ksr_route_natdetect();

    -- CANCEL processing
    ksr_route_cancel_process(request_method);

if ( request_method == "REGISTER") then
-- and nat_uac_test(64) 
--  and protocol=="wss") then 
        KSR.log("info", " KSR register, method " .. request_method .. " user_agent " .. user_agent .." proto "..protocol.."\n");
    -- register
    ksr_register(request_method);

end

    -- handle requests within SIP dialogs
    ksr_route_withindlg(request_method);

    -- handle retransmissions
    ksr_route_retrans_process();

    -- handle request without to tag
    ksr_route_request_process(request_method);
    return 1;
end

function ksr_register(request_method)
 -- Получаем SIP URI из заголовка From
    local from_uri = KSR.pv.get("$fu")
    
    -- Получаем значение Contact заголовка и проверяем поддержку WSS
    local contact = KSR.pv.get("$ct")
    KSR.log("err", "Register from :".. from_uri.. " contact :"..contact.."\n" )
--[[    local transport = KSR.pv.get("$ct.transport")
    
    if transport ~= "wss" then
        KSR.log("err", "Требуется WSS транспорт")
        KSR.sl.send_reply(400, "WSS Required")
        return -1
    end
]]--    
    -- Получаем значение expires из Contact заголовка
--[[    local expires = KSR.pv.get("$hdr(Expires)")
    if expires == nil then
        expires = KSR.pv.get("$ct.expires")
    end
]]--    
    -- Проверяем наличие обязательных полей
    if from_uri == nil or contact == nil then
        KSR.log("err", "Отсутствуют обязательные заголовки")
        KSR.sl.send_reply(400, "Bad Request")
        return -1
    end
--[[    
    -- Проверяем наличие WSS URI в контакте
    if not string.match(contact, "^wss://") then
        KSR.log("err", "Неверный формат WSS URI в Contact")
        KSR.sl.send_reply(400, "Invalid WSS Contact")
        return -1
    end
   
    -- Если expires = 0, то это запрос на удаление регистрации
    if expires == "0" then
        if KSR.usrloc.ul_rm_contact() < 0 then
            KSR.log("err", "Ошибка удаления WSS контакта")
            KSR.sl.send_reply(500, "Server Error")
            return -1
        end
    else
        -- Добавляем/обновляем WSS запись в location
        if KSR.usrloc.ul_add_contact() < 0 then
            KSR.log("err", "Ошибка добавления WSS контакта")
            KSR.sl.send_reply(500, "Server Error")
            return -1
        end
    end ]]--
    if KSR.auth_db.auth_check(KSR.kx.gete_fhost(), "subscriber", 1)<0 then
			        KSR.log("err", "AUth ok "..KSR.kx.gete_fhost())
			KSR.registrar.save("location",1)
                        KSR.auth.auth_challenge(KSR.kx.gete_fhost(), 0);
                        KSR.x.exit();
                end
                -- user authenticated - remove auth header
--                if not KSR.is_method_in("RP") then
--                        KSR.auth.consume_credentials();
--                end  

--    KSR.registrar.save("location",1)
    -- Отправляем успешный ответ с поддержкой WSS
    KSR.hdr.append("Sec-WebSocket-Protocol: sip\r\n")
    KSR.sl.send_reply(200, "OK")
    KSR.x.exit()
    return 1

end 


-- Per SIP request initial checks
--------------------------------------------
function ksr_route_reqinit()

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
    if request_method == "OPTIONS"
            and KSR.is_myself_ruri() 
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

            local ruser=KSR.kx.get_ruser()
          
            if  (KSR.regex.pcre_match(ruser,"^sip_user_[0-9][0-9][0-9][0-9]$"))>0 then  
                --and KSR.is_myself_ruri()  then  
                local sipuser = ruser..'@cw-kam1.skeef.su'
 --               KSR.xlog.xerr("iVINTE to WSS user  "..sipuser.."\n")

                local state = KSR.registrar.lookup("location")
                if state<0 then
                KSR.tm.t_newtran()
                    if state==-1 or state==-3 then
                        KSR.sl.send_reply(404, "Not Found")
                        KSR.x.exit()
                    elseif state==-2 then
                        KSR.sl.send_reply(405, "Method Not Allowed")
                        KSR.x.exit()
                    end    
                 end 
                  KSR.setflag(FLT_TO_WS) 
                  KSR.xlog.xerr("iVINTE to WSS user  "..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").."\n")
                          
            end    
        if ksr_route_direction() < 0 then
        -- Nasts disdcher 
        --  ksr_nats_disp()
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
-- кто инициатор
	 	int_dir=KSR.rr.is_direction("downstream")
		local hangup_party="0"
	   if int_dir==1 then
		  hangup_party="1"
		  KSR.xlog.xerr("BYE  send from caller to callee  :"..int_dir.."\n\r")
	   else
		  KSR.xlog.xerr("BYE  send from callee to caller :"..int_dir.."\n\r")
	   end
        KSR.pv.seti("$avp(hangup_party)",hangup_party)
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
        KSR.log("info", "328 in-dialog request,loose_route \n");
        ksr_route_dlguri();
        if request_method == "ACK" then 
           ksr_route_natmanage();
        end
        ksr_route_relay(request_method);
        KSR.x.exit()
    end

    KSR.log("info", "328 in-dialog request,not loose_route \n")
    if request_method == "ACK" then
        -- Relay ACK if it matches with a transaction ... Else ignore and discard
        if KSR.tm.t_check_trans() > 0 then
            -- no loose-route, but stateful ACK; must be an ACK after a 487 or e.g. 404 from upstream server
            KSR.log("info", "328 in-dialog request,not loose_route with transaction - relaying \n")
            ksr_route_relay(request_method);
        end
        KSR.log("err", "328 in-dialog request,not loose_route without transaction,exit the  \n")
        KSR.x.exit()
    end
    KSR.log("err", "328 received invalid sip packet,sending 404 \n");
    KSR.sl.sl_send_reply(404, "Not here");
    KSR.x.exit()
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_dlguri()
   Desc: -- URI update for dialog requests
------------------------------------------------------------------------------]]
function ksr_route_dlguri()
     KSR.log("err", " 387   ksr_route_dlguri  \n");
    if not KSR.isdsturiset() then
         KSR.log("err", "387 ksr_route_dlguri\n");
        KSR.nathelper.handle_ruri_alias()
    end
    return 1
end

--[[--------------------------------------------------------------------------
   Name: ksr_route_relay()
   Desc: adding the reply_route,failure_route,branch_route to request. relay the request.
------------------------------------------------------------------------------]]

function ksr_onreply_manage()
    KSR.info("incoming reply\n");
    if KSR.nathelper.nat_uac_test(64) > 0 then
           KSR.log("info", "589 adding contact alias  WSS\n")
           KSR.nathelper.add_contact_alias()
    end
    return 1;
end



function ksr_route_relay(req_method)

    local request_uri = KSR.pv.get("$ru") or ""
    local dest_uri = KSR.pv.get("$du") or ""

    local bye_rcvd = KSR.pv.get("$dlg_var(bye_rcvd)") or "false";

    if KSR.tm.t_is_set("branch_route") < 0 then
      KSR.tm.t_on_branch("ksr_branch_manage")
    end
    if KSR.tm.t_is_set("failure_route") < 0 and req_method == "INVITE" then
      KSR.tm.t_on_failure("ksr_failure_manage")
    end

    if req_method == "BYE" then
      if KSR.tm.t_is_set("branch_route") < 0 then
            KSR.tm.t_on_branch("ksr_branch_manage");
      end
      KSR.log("info", "sending delete command to rtpengine \n")

        local ruser=KSR.kx.get_ruser()

      if (KSR.regex.pcre_match(ruser,"^sip_user_[0-9][0-9][0-9][0-9]$"))>0 then
        KSR.xlog.xerr("after  reg mach iVINTE to WSS user \n")
        KSR.setbflag(FLT_TO_WS)
      end

      KSR.log("info", "463 INVITE before t set  \n")

    elseif req_method == "ACK" then
        if bye_rcvd ~= "true" and KSR.textops.has_body_type("application/sdp") > 0 then
            KSR.log("info", "request contains sdp, sending answer command to rtpengine \n")
            ksr_route_rtp_engine(req_method)


        end
    end
        if KSR.is_INVITE then

       --KSR.nathelper.handle_ruri_alias() -- !!!!!
       ksr_route_rtp_engine(req_method)
     end
    KSR.log("info", "WE ARE HERREEE \n")
    if KSR.is_method_in("ISU") then
        if KSR.tm.t_is_set("onreply_route") < 0 then
      KSR.xlog.xerr("onreply_route SETonreply_route SET \n")
          KSR.tm.t_on_reply("ksr_onreply_manage_rtpengine");
      end
    end
    if KSR.tm.t_is_set("onreply_route") < 0 then
        KSR.xlog.xerr("NOT SET \n")
    end
    if KSR.tm.t_relay() < 0 then
        KSR.sl.send_reply(500, "Server error")
    end
    KSR.x.exit()
end
--[[--------------------------------------------------------------------------
   Name: ksr_route_natdetect()
   Desc: caller NAT detection and add contact alias
------------------------------------------------------------------------------]]
function ksr_route_natdetect()
    KSR.force_rport()
--    if KSR.nathelper.nat_uac_test(19) > 0 then
--       KSR.log("info", "request is behind nat \n")
--        if KSR.is_REGISTER() then
--           KSR.nathelper.fix_nated_register();
--        end     
--        if KSR.siputils.is_first_hop() > 0 then
--            KSR.log("info", "adding contact alias \n")
--            KSR.nathelper.set_contact_alias()
--        end
--        KSR.setflag(FLT_NATS);
--    end

    if KSR.nathelper.nat_uac_test(64) > 0 then
        KSR.log("info", "request is behind nat WSS \n")
        if KSR.is_REGISTER() then
            KSR.log("info", "Register contact alias  WSS\n")
            KSR.nathelper.fix_nated_register();
        end   
        if KSR.siputils.is_first_hop() > 0 then
            KSR.log("info", "adding contact alias  WSS\n")
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
                KSR.log("info", "ENTER check_route_param nat \n")
    if KSR.siputils.is_request() > 0 then
        if KSR.siputils.has_totag() > 0 then
            if KSR.rr.check_route_param("nat=yes") > 0 then
                KSR.setbflag(FLB_NATB);
                KSR.log("info", "552 check_route_param nat \n")
            elseif KSR.rr.check_route_param("rtp=bridge") > 0 then
                KSR.setbflag(FLB_BRIDGE);
                KSR.log("info", "552 check_route_param brigdge \n")
            elseif KSR.rr.check_route_param("rtp=ws") > 0 then
                KSR.setbflag(FLB_RTPWS);
                KSR.log("info", "552 check_route_param ws \n")
             elseif KSR.rr.check_route_param("transport=ws") > 0 then
                KSR.setbflag(FLB_RTPWS);
                KSR.log("info", "552 check_route_param transport ws \n")    
	    end

        end
    end
    KSR.log("info", "ENTER2  check_route_param nats \n")
--..KSR.isflagset(FLT_NATS).. "natb "..KSR.isbflagset(FLB_NATB).." \n")
if KSR.rr.check_route_param("rtp=ws") > 0 then
                KSR.log("info", "!!!! check_route_param rtp=ws param  \n")
	    end
if (KSR.isflagset(FLB_RTPWS)) then
                KSR.log("info", "!!!! check_route_param rtp=ws flag  \n")
	    end


    if (not (KSR.isflagset(FLT_NATS) or KSR.isbflagset(FLB_NATB))) then
        return 1;
    end

    KSR.log("info", "ENTER3  check_route_param nats \n")

    if KSR.siputils.is_request() > 0 then
        if not KSR.siputils.has_totag() then
            if KSR.tmx.t_is_branch_route() > 0 then
                KSR.rr.add_rr_param(";nat=yes")
            end
        end
    elseif KSR.siputils.is_reply() > 0 then
        if KSR.isbflagset(FLB_NATB) or KSR.isbflagset(FLT_TO_WS) then
            KSR.nathelper.set_contact_alias()
            KSR.xlog.xerr("ADD alias \n")
        end
 --       KSR.nathelper.set_contact_alias() --!!!!!! for test
    end
    KSR.log("info", "ENTER4  check_route_param nats \n")
    return 1;
end

--[[--------------------------------------------------------------------------
   Name: ksr_branch_manage()
   Desc: managing outgoing branch
------------------------------------------------------------------------------]]



function ksr_reply_route()
	KSR.info("===== response - from kamailio lua script\n");
	return 1;
end


--[[--------------------------------------------------------------------------
   Name: ksr_onreply_manage()
   Desc: managing incoming response for the request
------------------------------------------------------------------------------]]
--[[--------------------------------------------------------------------------
   Name: ksr_onreply_manage_answer()
   Desc: managing incoming response for the request and sending answer command to
   rtpengine
------------------------------------------------------------------------------]]

function ksr_onreply_manage_rtpengine()
    local rtpengine=""
    local bye_rcvd = KSR.pv.get("$dlg_var(bye_rcvd)") or "false";
    KSR.log("info", "630  response contains sdp, answer to rtpengine bye_rcvd :"..bye_rcvd.." \n")
        local dp_wss=KSR.pv.gete("$dP") 
        local tp_wss=KSR.rr.check_route_param("transport=wss")
        local to_wss=0 
if bye_rcvd ~= "true" and KSR.textops.has_body_type("application/sdp") > 0 then
    if KSR.is_WSX() then
            to_wss="yes"
            KSR.setflag(FLB_RTPWS);
            KSR.log("info", "630 check_route_param ws \n")
            rtpengine = "address-family=IP4  rtcp-mux-demux DTLS=off SDES-off ICE=remove RTP/AVP  full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";     
            KSR.log("info", "630  response contains sdp, answer to rtpengine dp"..dp_wss.." transport "..tp_wss.." is to_wss "..to_wss.."\n")
--    else
        KSR.log("info", "630  response contains sdp, answer to rtpengine dp"..dp_wss.." transport "..tp_wss.." is to_wss "..to_wss.."\n")     
--[[
        if KSR.rr.check_route_param("transport=wss") > 0 then
                KSR.setflag(FLB_RTPWS);
                KSR.log("info", "630 check_route_param ws \n")
            rtpengine2 = "address-family=IP4  rtcp-mux-demux DTLS=off SDES-off ICE=remove RTP/AVP  full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";     
        end 
        if (KSR.isflagset(FLT_TO_WS)) then 
                KSR.log("info", "630 check_route_param flag set  FLT_TO_WS \n")
                rtpengine2 = "address-family=IP4  rtcp-mux-demux DTLS=off SDES-off ICE=remove RTP/AVP  full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";
        end  
]]--

        if (KSR.isflagset(FLT_FROM_ASTERISK)) then
            rtpengine = "ICE=remove RTP/AVP full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";
            KSR.log("info", "630 check_route_param from Asterisk \n")
        elseif (KSR.isflagset(FLT_FROM_PROVIDER)) then ]]--
            rtpengine = "ICE=remove RTP/AVP full-rtcp-attribute direction=priv direction=pub replace-origin replace-session-connection";
            KSR.log("info", "630 check_route_param from prov \n")
        end
    end    

    if rtpengine~="" then
        if KSR.rtpengine.rtpengine_manage(rtpengine) > 0  then
            KSR.log("info", "received success reply for rtpengine answer from instance"..rtpengine.." \n")
        else
            KSR.log("err", "received failure reply for rtpengine answer from instance \n")
        end
    end
end 
    ksr_onreply_manage();
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
    KSR.log("err", "failure route: " .. request_method .. " incoming reply received - " ..tostring(response_code).." " .. tostring(reply_type) .." ".. tostring(reason_phrase) .. "\n")

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
		KSR.xlog.xerr("ds 401 row 460")
     if KSR.dispatcher.ds_select_next > 0 then
	KSR.xlog.xerr("ds 401 row 462")
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
	KSR.xlog.xerr("request-uri - " .. tostring(KSR.pv.get("$ru")) .. "\n")
        local request_method = KSR.pv.get("$rm") or "";
--	KSR.log("info","from "..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
	KSR.xlog.xerr("ds from "..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
   --	KSR.pv.sets("$td","10.128.0.52")
        ksr_route_relay(request_method);
    else
        KSR.xlog.xerr("dispatcher lookup failed" .. "\n")
        KSR.x.exit()
    end
end


function ksr_route_direction()
    local dispatch_set = 1
    local dispatch_sbm = 2 
    if KSR.dispatcher.ds_is_from_lists() > 0 then
        KSR.xlog.xerr("info","Call from Asterisk " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
        KSR.setflag(FLT_FROM_ASTERISK);
        return 1
    elseif KSR.isbflagset(FLT_TO_WS) then 
        KSR.xlog.xerr("Call from Asterisk to WS FLT_TO_WS " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
        return 1  
    else
       KSR.xlog.xerr("ds Call from Provider " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
  --     KSR.log("info","Call from Provider " ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
       KSR.setflag(FLT_FROM_PROVIDER);
       return -1
    end
end



function ksr_nats_disp()
--	    KSR.tm.t_newtran()
        KSR.tm.t_set_fr(3000)
        KSR.sl.sl_send_reply("100", "suspend")
    if(KSR.tmx.t_suspend()<0) then
          KSR.xlog.xerr("ksr_nats_disp" ..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."")
          KSR.sl.sl_send_reply("500", "nats disp")
          KSR.x.exit()
    end
    local key=KSR.pv.get("$(ci{s.md5})")
        local id_index = KSR.pv.get("$T(id_index)")
        local id_label = KSR.pv.get("$T(id_label)")
    KSR.htable.sht_sets("siptmx",key,id_index..":"..id_label )

       local nats_disp=string.format('{"key":"%s","from":"%s","to":"%s","domen":"%s","kama":"%s"}',key, KSR.kx.get_fuser(), KSR.kx.get_tuser(),KSR.pv.get("$fd"),getHostname())
	    KSR.warn(" get_nats  Nats dialog_s send:"..nats_disp.."\n\r")
    KSR.nats.publish("kama_icb" , nats_disp);
    KSR.x.exit()
end


function ksr_nats_forward()

 local dst=KSR.pv.gete('$var(nats_dst)')
 KSR.warn("get_nats. "..dst.." dst \n" )
 KSR.pv.sets('$du', dst)
	KSR.hdr.append('X-DOMEN-2: '..KSR.pv.gete("$fd")..'\r\n')
	KSR.hdr.append('X-kam : ' ..getHostname()..'\r\n')
--    KSR.tm.t_relay() 
end



function ksr_route_dispatcher_select()
--    local routing_policy = 4;
      local routing_policy = 9;	
    local dispatch_set = 1;
    local disp=KSR.htable.sht_get( "disp",KSR.kx.get_srcip() );
      -- проверка куда направлять водящие
	local disp=KSR.htable.sht_get( "disp",KSR.kx.get_srcip() );
 --[[       if disp~=nil then
	    KSR.log("info","526 dispatch group "..disp.."")
--	    dispatch_set = disp;
--	    KSR.hdr.append('X-tar: 0\n\r')
        else
	    KSR.log("info","526 NOT dispatch group ")
        end
	local to_n=KSR.kx.get_tuser()

	if to_n.len(to_n)>=12 or to_n=="9651795060"  then
	    dispatch_set=1
	    KSR.log("info","532 Len dispatch group ")
	else 
--	    dispatch_set=2
--	    routing_policy = 11
	    KSR.log("info","532 Len dispatch group to cur ")
	end
--        KSR.pv.seti("avp(disp_on_f)",dispatch_set)

    KSR.log("err","!!!string_ip "..tostring(KSR.kx.get_srcip()).." to "..to_n.. " len "..to_n:len().." Dispacher "..dispatch_set.."\n\r")
]]--
    if KSR.dispatcher.ds_select_dst(dispatch_set, routing_policy) > 0 then
	if  dispatch_set==2 then 
        KSR.tm.t_on_failure("ksr_failure_dispacher")
	end
        KSR.log("info", "request-uri - " .. tostring(KSR.pv.get("$ru")) .. "\n")
        local request_method = KSR.pv.get("$rm") or "";
        local dest_uri = KSR.pv.get("$fu") or ""
	local df = KSR.pv.get("$fd") or ""
	KSR.log("info","Dispatcher from"..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."  dst uri "..dest_uri.."")
	KSR.xlog.xerr("ds  Dispatcher from"..KSR.kx.get_furi().." dst "..KSR.pv.get("$ru").." src "..KSR.kx.get_srcip().."  dst uri "..dest_uri.."")
	KSR.hdr.append('X-DOMEN: '..df..'\r\n')
	KSR.hdr.append('X-kam : ' ..getHostname()..'\r\n')
    else
        KSR.log("err", "dispatcher lookup failed" .. "\n")
        KSR.x.exit()
    end
end


function ksr_failure_dispacher()
    local response_code = KSR.pv.gete("$rs")
    local du = KSR.pv.get("$du") or ""
--    local disp_set=KSR.pv.get("avp(disp_on_f)") or "" 
--    	KSR.warn("ds  Dispatcher fail "..response_code.." disp set "..disp_set.." dst "..KSR.pv.get("$ru").." du  "..du.."")
    if KSR.tm.t_check_status("408|603") then
--    if KSR.tm.t_check_status("408") then
	KSR.dispatcher.ds_next_dst()
    	KSR.warn("ds  Dispatcher from faild next"..KSR.pv.get("$du"))
	KSR.tm.t_on_failure("ksr_failure_dispacher")
	KSR.tm.t_relay("ksr_onreply_manage")
	KSR.x.exit()
    end
end



function ksr_route_rtp_engine(req_method)
    if req_method == "INVITE" then 
          local to_wss=0
        if KSR.to_WSX() then
            to_wss="yes"
            KSR.xlog.xerr("834 Flag is set FLT_TO_WS  in retpengie   \n")
            local rtp_option="via-branch=auto record-call=yes  metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser().."" 
            rtpengine = rtp_option.." replace-origin replace-session-connection via-branch=auto address-family=IP4 rtcp-mux-offer generate-mid DTLS=passive SDES-off ICE=force RTP/SAVPF direction=priv direction=pub"     
        elseif (KSR.isflagset(FLT_FROM_ASTERISK)) then
	       local rtp_option="via-branch=auto record-call=yes  metadata=from:"..KSR.kx.get_fuser().."|to:"..KSR.kx.get_tuser()..""    
    	   rtpengine = rtp_option.." ICE=remove RTP/AVP full-rtcp-attribute direction=priv direction=pub replace-origin replace-session-connection";
        elseif (KSR.isflagset(FLT_FROM_PROVIDER)) then
		      local rtp_option="via-branch=auto record-call=yes   metadata=from:"..KSR.kx.get_tuser().."|to:"..KSR.kx.get_fuser()
    	       rtpengine =rtp_option.." ICE=remove codec-strip=all codec-offer=PCMA   transcode=telephone-event always-transcode RTP/AVP full-rtcp-attribute direction=pub direction=priv replace-origin replace-session-connection";               
        end 
        KSR.log("info", "834 received success reply for rtpengine answer from instance ksr_route_rtp_engine to_wss "..to_wss.."\n")
--[[        
        if (KSR.isflagset(FLT_TO_WS)) then
              --         rtpengine = rtp_option.." replace-origin replace-session-connection via-branch=auto address-family=IP4 rtcp-mux-demux generate-mid DTLS=passive SDES-off ICE=force RTP/SAVPF direction=priv direction=pub"
        end 
]]--
       if KSR.rtpengine.rtpengine_manage(rtpengine) > 0 then
            KSR.log("info", "received success reply for rtpengine answer from instance ksr_route_rtp_engine \n")
-- Проверка на передачу rtp premedia 
	    if (KSR.isflagset(FLT_FROM_ASTERISK)) and KSR.pv.get("$avp(dao)") ==1 then
		KSR.log("info", "522 X-ao recive_forward V "..KSR.pv.get("$avp(dao)").." trunk " ..KSR.pv.gete("$avp(trunk)").. "\n")
		KSR.route("rt_forward_start")
	    end 
        else
            KSR.log("err", "received failure reply for rtpengine answer from instance \n")
	     KSR.sl.sl_send_reply("540", "too many rtpengine sessions")
             KSR.x.drop();
        end
   end

    if req_method == "ACK" or req_method == "BYE"  then
        KSR.rtpengine.rtpengine_manage()
    end

   return 1;

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
   Name: ksr_xhttp_event(evname)
   Desc: http request and response handling
------------------------------------------------------------------------------]]
--[[
function ksr_xhttp_event(evname)
    local rpc_method = KSR.pv.get("$rm") or ""
    if ((rpc_method == "POST" or rpc_method == "GET")) then
        if KSR.xmlrpc.dispatch_rpc() < 0 then
            KSR.log("err", "error while executing xmlrpc event" .. "\n")
        end
    end
    return 1
end
]]--
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

function ksr_xhttp_event(evname)
    local rpc_method = KSR.pv.get("$rm") or ""
    xhttp_prom_root=KSR.pv.get("$(hu{s.substr,0,8})")
            KSR.log("err", "xhttp executing rpc event " ..xhttp_prom_root.." metod "..rpc_method.."\n")

    if xhttp_prom_root =="/XMLRPC" then
        if ((rpc_method == "POST" or rpc_method == "GET")) then
            if KSR.xmlrpc.dispatch_rpc() < 0 then
                KSR.log("err", "error while executing xmlrpc event" .. "\n")
	        else 
	           KSR.xhttp.xhttp_reply("200",  "reason", "ctype","ok");
            end
--	        KSR.xhttp.xhttp_reply("200",  "reason", "ctype","ok");
	        KSR.xhttp.xhttp_reply(200, "OK", "application/json", "")
--	        xhttp_reply("200", "OK", "" , "");
	        KSR.x.exit()
        end
    end
  if xhttp_prom_root =="/RPC" then
--    if ((rpc_method == "POST" or rpc_method == "GET")) then
	    hu=KSR.pv.get("$hu")
        KSR.log("err", "RPC while executing Jsonrpc event" ..hu.. "\n")
        KSR.jsonrpcs.dispatch()
    --if KSR.jsonrpcs.dispatch_rpc() < 0 then
    --    if KSR.jsonrpc_dispatch()< 0 then
    --        KSR.log("err", "error while executing Jsonrpc event" .. "\n")
	--else 
--	     KSR.xhttp.xhttp_reply("200",  "reason", "ctype","ok");
	       KSR.xhttp.xhttp_reply(200, "OK", "application/json", "")
	       KSR.x.exit()
      ---  end
--      end
  end

--[[
 if ($hu =~ "^/RPC") {
        xlog("L_INFO", "jsonrpc dispatch [$hu] [$var(x)]");
        jsonrpc_dispatch();
        return;
    }
]]--
  if xhttp_prom_root =="/ws" then
	    KSR.set_reply_close()
	    KSR.set_reply_no_connect()
            KSR.log("err", "WSS  error while executing xmlrpc event " ..KSR.pv.get("$hdr(Upgrade)").."  conect "..KSR.pv.get("$hdr(Connection)").." proto "..rpc_method.. "\n")

	    KSR.websocket.handle_handshake();
	if (KSR.pv.get("$hdr(Upgrade)")=="websocket" and KSR.pv.get("$hdr(Connection)")=="Upgrade"  and rpc_metod=="GET" )then
            KSR.log("err", "WSS 22  error while executing xmlrpc event" .. "\n")
	    if KSR.websocket.handle_handshake() > 0 then
            KSR.info("handshak ok \n")
        else
            KSR.err("handshake err \n")
        end
--		KSR.xhttp.xhttp_reply("200",  "reason", "ctype","Not found");
	end 
  end 

    KSR.log("err","hu  "..KSR.pv.get("$hu").." парсер "..KSR.pv.get("$(hu{s.substr,0,8})") )
    xhttp_prom_root=KSR.pv.get("$(hu{s.substr,0,8})")

    if xhttp_prom_root =="/metrics" then
        KSR.log("info","Called metrics")
    end 
    return 1
end
function ksr_ws_event(evname)
            KSR.log("err", "error while executing xmlrpc event" ..KSR.pv.get("$ws_conid").. "\n")

end 

--[[--------------------------------------------------------------------------
   Name: ksr_nats_event(evname)
   Desc: get the dispatch domain from nats 
------------------------------------------------------------------------------]]

function ksr_nats_event(evname)
--    KSR.xlog.info("===== nats module received event: "..evname ..", data:"..KSR.pv.gete('$natsData').."\n");
    if (evname == "nats:siptmx_be") then
        KSR.warn("get_nats. "..KSR.pv.gete('$natsData').."\n" )
        local key= KSR.pv.gete('$(natsData{json.parse, key})')
        local dst= KSR.pv.gete('$(natsData{json.parse, domen})')
        KSR.warn("get_nats. "..key.." dst ".. dst.."\n" )
        local key_idx=KSR.htable.sht_gete("siptmx",key)

        if not key_idx then 
	KSR.warn("get_nats.Not find trnsaktion  "..key.." dst ".. dst.."\n" )
	KSR.x.exit()
        end 

        tindex, tlabel = key_idx:match("(.+):(.+)")
        KSR.warn("get_nats. "..tindex.." lab "..tlabel.."\n" )
        KSR.pv.sets('$var(nats_dst)', dst)
        KSR.tmx.t_continue(tindex, tlabel, "ksr_nats_forward")
    end
end 

--[[--------------------------------------------------------------------------
   Name: ksr_dispatcher_event(evname)
   Desc: get up/down status  dispatch domain send nats 
------------------------------------------------------------------------------]]
function ksr_dispatcher_event(evname)
        KSR.log("info","Dispatcher event "..evname.."  rm " ..KSR.pv.gete('$rm') .." Ru "..KSR.pv.gete('$ru') .."\n");
    KSR.nats.publish("asterisk_status" , "{'kama':'"..getHostname().."','sip-gw':'"..KSR.pv.gete('$ru').."','status':'"..evname.."'}");


end


--[[--------------------------------------------------------------------------
   Name: ksr_dialog_event(evname)
   Desc: get the dispatch domain from the dispatcher list based on policy
------------------------------------------------------------------------------]]

function ksr_dialog_event(evname)
        KSR.xlog.xerr("in dialog event callback with event-name - " .. evname .. "\n")
        local call_id = KSR.pv.get("$ci")

if (evname == "dialog:start")  then
-- and     KSR.isflagset(FLT_FROM_ASTERISK)    then
        nat_s=string.format('{"call_id":"%s","from":"%s","to":"%s","kama":"%s","status":"start"}',call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser(),getHostname())
        nat_s2=string.format('{"call_id":"%s","from":"%s","to":"%s","kama":"%s","status":"start"}',tostring(call_id), tostring(KSR.kx.get_fuser()),tostring(KSR.kx.get_tuser()),getHostname())
	KSR.xlog.xerr("Nats dialog_s send:"..nat_s.."\n\r")
        KSR.nats.publish("call_info" , nat_s);
-- Enable record disable forward
KSR.route("rt_forward_start")
--	if KSR.pv.get("$avp(dao)") ==1 then	KSR.route("rt_forward_stop") end
		KSR.rtpengine.start_recording();
-- get timeshtamp 
	local	start_time=KSR.pv.get("$TS")
	KSR.xlog.xerr("Nats start time:"..start_time.."\n\r")
        KSR.htable.sht_sets("bsec",call_id,start_time )
    --    KSR.pv.seti('$var(start_time)', start_time)
--	KSR.dialog.dlg_set_var(
    	KSR.xlog.xerr("Nats dialog_s time:"..start_time.." nomer "..tostring(KSR.kx.get_fuser()).."\n")
--  
end 

            
if (evname == "dialog:end") then
	local hangup_party=KSR.pv.get("$avp(hangup_party)")
        local start_time=KSR.htable.sht_gete("bsec",call_id)
	KSR.xlog.xerr("B sec "..start_time .."\n")
	KSR.htable.sht_rm("bsec",call_id)
--        local f_bye= KSR.pv.gete('$(route_uri{uri.param,from_tag}{s.select,0,;})')
        local f_bye= KSR.pv.gete('$route_uri')
--	  start_time=KSR.pv.get('$avp(start_time)')
--	  local	start_time=KSR.pv.get('$var(start_time)')
	local 	end_time=KSR.pv.get("$Ts")
	KSR.xlog.xerr("Nats dialog_s1 f_bye "..f_bye.."  time:"..start_time.." End "..end_time.." bc " ..end_time-start_time.." nomer "..tostring(KSR.kx.get_fuser()).."\n")            

        nat_s=string.format('{"call_id":"%s","from":"%s","to":"%s","kama":"%s","bilsec":"%s","hangup_party":"%s","status":"end"}',call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser(),getHostname(),end_time-start_time,hangup_party)
	KSR.xlog.xerr("Nats dialog_e send:"..nat_s.."\n\r")
        KSR.nats.publish("rec_id" , nat_s)
--	local time = os.time()
--    	KSR.xlog.xerr("Nats dialog_s2 time:"..start_time.." End os"..time.. " END "..end_time .. " bc " ..time-start_time.." nomer "..tostring(KSR.kx.get_fuser()).."\n\r")            
	KSR.rtpengine.rtpengine_delete("");
end

if (evname == "dialog:failed") then
        nat_s=string.format('{"call_id":"%s","from":"%s","to":"%s","kama":"%s","status":"failed"}',call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser(),getHostname())
	    KSR.log("info","Nats dialog_e send:"..nat_s.."\n\r")
    KSR.nats.publish("rec_id" , nat_s);
--KSR.rtpengine.rtpengine_delete("");
end
if (evname == "dialog:unknown") then
        nat_s=string.format('{"call_id":"%s","from":"%s","to":"%s","kama":"%s","status":"unknown"}',call_id, KSR.kx.get_fuser(), KSR.kx.get_tuser(),getHostname())
	    KSR.log("info","Nats dialog_e send:"..nat_s.."\n\r")
    KSR.nats.publish("rec_id" , nat_s);
    end

end

-- event callback function implemented in Lua
function ksr_tm_event(evname)
    KSR.info("===== tm module triggered event: " .. evname .. "\n");
    KSR.xlog.xerr("BRANCH FAILED:".. KSR.pv.gete('$sel(via[1].branch)') .." " ..KSR.pv.gete('$T_branch_idx'))
    return 1;
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

