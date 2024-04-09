kamctl rpc app_lua.reload
kamcmd  htable.flush ipban
#top -c -p $(kamcmd ps | grep receiver | awk '{ print $1 }' | xargs | tr ' ' ,)
echo "">/var/log/sip/kamailio.log
echo "">/var/log/sip/rtpengine.log
echo "">/var/log/sip/rtpengine_cdr.log
echo "">/var/log/sip/rtpengine_rtcp.log
