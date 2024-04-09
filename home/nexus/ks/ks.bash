#top -c -p $(kamcmd ps | grep receiver | awk '{ print $1 }' | xargs | tr ' ' ,)
echo "">/var/tmp_log/kam_local7.log
echo "">/var/tmp_log/rtpengine.log
echo "">/var/tmp_log/rtpengine_cdr.log
echo "">/var/tmp_log/rtpengine_rtcp.log
kamctl rpc app_lua.reload
kamcmd  htable.flush ipban
