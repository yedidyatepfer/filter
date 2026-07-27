//remote address: 68.174.90.29
//ip: v4
//port: 41653
//last seen ip: 68.174.90.29
//last seen age: 0
function FindProxyForURL(url, host) {
	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "1.1.1.1", "255.255.255.0")
	if(isInNet(dnsResolve(host), "1.1.1.1", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isPlainHostName(host)
	if(isPlainHostName(host)) return "DIRECT";

	//FROM RULE: BYPASS:url.substring(0, 4)=="ftp:"
	if(url.substring(0, 4)=="ftp:") return "DIRECT";

	//FROM RULE: BLOCK:isInNet(dnsResolve(host), "192.229.211.108", "255.255.255.0")
	if(isInNet(dnsResolve(host), "192.229.211.108", "255.255.255.0")) return "PROXY 0.0.0.0:1234";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")
	if(isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")
	if(isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "100.64.0.0", "255.192.0.0")
	if(isInNet(dnsResolve(host), "100.64.0.0", "255.192.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.0.2.0", "255.255.255.0")
	if(isInNet(dnsResolve(host), "192.0.2.0", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")
	if(isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.0.0.0", "255.255.255.0")
	if(isInNet(dnsResolve(host), "192.0.0.0", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "169.254.0.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "169.254.0.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tmodns.net")
	if(dnsDomainIs(host, "tmodns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gentechsolution.com")
	if(dnsDomainIs(host, "gentechsolution.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rndsoftwaregroup.com")
	if(dnsDomainIs(host, "rndsoftwaregroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gthelps.com")
	if(dnsDomainIs(host, "gthelps.com")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "51.89.148.40", "255.255.255.0")
	if(isInNet(dnsResolve(host), "51.89.148.40", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.157.84.181", "255.255.255.0")
	if(isInNet(dnsResolve(host), "192.157.84.181", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"54.36.160.119","255.255.255.0")
	if(isInNet(dnsResolve(host),"54.36.160.119","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"91.121.215.119","255.255.255.0")
	if(isInNet(dnsResolve(host),"91.121.215.119","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"63.130.172.43","255.255.255.0")
	if(isInNet(dnsResolve(host),"63.130.172.43","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"be101.lon1-eri1-g2-nc5.uk.eu")
	if(dnsDomainIs(host,"be101.lon1-eri1-g2-nc5.uk.eu")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"ns631136604.ip-54-36-160.eu")
	if(dnsDomainIs(host,"ns631136604.ip-54-36-160.eu")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, ".local")
	if(shExpMatch(host, ".local")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guzzoni.apple.com")
	if(dnsDomainIs(host, "guzzoni.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive.apple.com")
	if(dnsDomainIs(host, "captive.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive-cidr.origin-apple.com.akadns.net")
	if(dnsDomainIs(host, "captive-cidr.origin-apple.com.akadns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive-cdn.origin-apple.com.akadns.net")
	if(dnsDomainIs(host, "captive-cdn.origin-apple.com.akadns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive.g.aaplimg.com")
	if(dnsDomainIs(host, "captive.g.aaplimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "a.gslb.aaplimg.com")
	if(dnsDomainIs(host, "a.gslb.aaplimg.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "airpot.us")
	if(dnsDomainIs(host, "airpot.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "itools.info")
	if(dnsDomainIs(host, "itools.info")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ibook.info")
	if(dnsDomainIs(host, "ibook.info")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "thinkdifferent.us")
	if(dnsDomainIs(host, "thinkdifferent.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gateway-carry.icloud.com")
	if(dnsDomainIs(host, "gateway-carry.icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "network-auth.com")
	if(dnsDomainIs(host, "network-auth.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "hs-auth-aqx.cequintvzwecid")
	if(dnsDomainIs(host, "hs-auth-aqx.cequintvzwecid")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tmocce.com")
	if(dnsDomainIs(host, "tmocce.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "intelligenthome.timewarnercable.com")
	if(dnsDomainIs(host, "intelligenthome.timewarnercable.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "spectrum.com")
	if(shExpMatch(host, "spectrum.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.xfinity.com")
	if(dnsDomainIs(host, "login.xfinity.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "boingohotspot.net")
	if(dnsDomainIs(host, "boingohotspot.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "boingo.com")
	if(dnsDomainIs(host, "boingo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "boingo.events")
	if(dnsDomainIs(host, "boingo.events")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "jetblue.com")
	if(dnsDomainIs(host, "jetblue.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, ".united.com")
	if(dnsDomainIs(host, ".united.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifi.united.com")
	if(dnsDomainIs(host, "wifi.united.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "www.united.com")
	if(dnsDomainIs(host, "www.united.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "unitedwifi.com")
	if(dnsDomainIs(host, "unitedwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "deltawifi.com")
	if(dnsDomainIs(host, "deltawifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "flyfi.com")
	if(dnsDomainIs(host, "flyfi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "www.flyfi.com")
	if(dnsDomainIs(host, "www.flyfi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gogoair.com")
	if(dnsDomainIs(host, "gogoair.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gogo.com")
	if(dnsDomainIs(host, "gogo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gogoinflight.com")
	if(dnsDomainIs(host, "gogoinflight.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive.gogoinflight.com")
	if(dnsDomainIs(host, "captive.gogoinflight.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "airborne.gogoinflight.com")
	if(dnsDomainIs(host, "airborne.gogoinflight.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "elal.co.il")
	if(dnsDomainIs(host, "elal.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "elal.co")
	if(dnsDomainIs(host, "elal.co")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "elal-matmid.com")
	if(dnsDomainIs(host, "elal-matmid.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifi.elal.com")
	if(dnsDomainIs(host, "wifi.elal.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "selsctnetworx.com")
	if(shExpMatch(host, "selsctnetworx.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, ".spirit.com")
	if(dnsDomainIs(host, ".spirit.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(host, "msftconnecttest.com")
	if(shExpMatch(host, "msftconnecttest.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "air2data.com")
	if(dnsDomainIs(host, "air2data.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "virgin-atlantic-wifi.com")
	if(dnsDomainIs(host, "virgin-atlantic-wifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "virginatlantic.com")
	if(dnsDomainIs(host, "virginatlantic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guestwifi-us.skyfii.com")
	if(dnsDomainIs(host, "guestwifi-us.skyfii.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "connectivitycheck.gstatic.com")
	if(dnsDomainIs(host, "connectivitycheck.gstatic.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "inflight-wifi.com")
	if(dnsDomainIs(host, "inflight-wifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "aainflight.com")
	if(dnsDomainIs(host, "aainflight.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "viasat.com")
	if(dnsDomainIs(host, "viasat.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "viasat-online.com")
	if(dnsDomainIs(host, "viasat-online.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "inflight-online.com")
	if(dnsDomainIs(host, "inflight-online.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifi.londoncityairport.com")
	if(dnsDomainIs(host, "wifi.londoncityairport.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifionboard.com")
	if(dnsDomainIs(host, "wifionboard.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "turktelekomwififly.com")
	if(dnsDomainIs(host, "turktelekomwififly.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "flynet.com")
	if(dnsDomainIs(host, "flynet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "getconnected.southwestwifi.com")
	if(dnsDomainIs(host, "getconnected.southwestwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cmyip.com")
	if(dnsDomainIs(host, "cmyip.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "finnair.com")
	if(dnsDomainIs(host, "finnair.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "captive.inflightinternet.com")
	if(dnsDomainIs(host, "captive.inflightinternet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.attwifi.com")
	if(dnsDomainIs(host, "login.attwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guestwifi.united.com")
	if(dnsDomainIs(host, "guestwifi.united.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.bell.net")
	if(dnsDomainIs(host, "imap.bell.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mailspamprotection.com")
	if(dnsDomainIs(host, "mailspamprotection.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "emailsrvr.com")
	if(dnsDomainIs(host, "emailsrvr.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "scilearn.com")
	if(dnsDomainIs(host, "scilearn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.jnet.com")
	if(dnsDomainIs(host, "smtp.jnet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imtp.jnet.com")
	if(dnsDomainIs(host, "imtp.jnet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "pop.yeshivanet.com")
	if(dnsDomainIs(host, "pop.yeshivanet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.yeshivanet.com")
	if(dnsDomainIs(host, "smtp.yeshivanet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.gmail.com")
	if(dnsDomainIs(host, "imap.gmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.gmail.com")
	if(dnsDomainIs(host, "smtp.gmail.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.gmail.co.il")
	if(dnsDomainIs(host, "imap.gmail.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.gmail.co.il")
	if(dnsDomainIs(host, "smtp.gmail.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.me.com")
	if(dnsDomainIs(host, "mail.me.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.mail.me.com")
	if(dnsDomainIs(host, "imap.mail.me.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.yahoo.com")
	if(dnsDomainIs(host, "imap.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apple.imap.mail.yahoo.com")
	if(dnsDomainIs(host, "apple.imap.mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.yahoo.com")
	if(dnsDomainIs(host, "smtp.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.yahoo.com")
	if(dnsDomainIs(host, "mail.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.aol.com")
	if(dnsDomainIs(host, "imap.aol.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.aol.com")
	if(dnsDomainIs(host, "smtp.aol.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mail.aol.com")
	if(dnsDomainIs(host, "mail.aol.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.mail.aol.com")
	if(dnsDomainIs(host, "imap.mail.aol.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.juno.com")
	if(dnsDomainIs(host, "smtp.juno.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "pop.juno.com")
	if(dnsDomainIs(host, "pop.juno.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.office365.com")
	if(dnsDomainIs(host, "smtp.office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outlook.office365.com")
	if(dnsDomainIs(host, "outlook.office365.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap-mail.outlook.com")
	if(dnsDomainIs(host, "imap-mail.outlook.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp-mail.outlook.com")
	if(dnsDomainIs(host, "smtp-mail.outlook.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.secureserver.net")
	if(dnsDomainIs(host, "imap.secureserver.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtpout.secureserver.net")
	if(dnsDomainIs(host, "smtpout.secureserver.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.ipage.com")
	if(dnsDomainIs(host, "smtp.ipage.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "pop.ipage.com")
	if(dnsDomainIs(host, "pop.ipage.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "imap.ionos.com")
	if(dnsDomainIs(host, "imap.ionos.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.ionos.com")
	if(dnsDomainIs(host, "smtp.ionos.com")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "apple.com/library/test/success.html")
	if(shExpMatch(url, "apple.com/library/test/success.html")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "iosapps.itunes.apple.com")
	if(dnsDomainIs(host, "iosapps.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, ".icloud.com")
	if(dnsDomainIs(host, ".icloud.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "icloud-content.com")
	if(dnsDomainIs(host, "icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "blobstore.apple.com")
	if(dnsDomainIs(host, "blobstore.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.smoot.apple.com")
	if(dnsDomainIs(host, "api.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api-glb-nyc.smoot.apple.com")
	if(dnsDomainIs(host, "api-glb-nyc.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ca.iadsdk.apple.com")
	if(dnsDomainIs(host, "ca.iadsdk.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kt-prod.apple.com")
	if(dnsDomainIs(host, "kt-prod.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api-use1a.smoot.apple.com")
	if(dnsDomainIs(host, "api-use1a.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api-glb-use1b.smoot.apple.com")
	if(dnsDomainIs(host, "api-glb-use1b.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mesu.apple.com")
	if(dnsDomainIs(host, "mesu.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bag.itunes.apple.com")
	if(dnsDomainIs(host, "bag.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdn.smoot.apple.com")
	if(dnsDomainIs(host, "cdn.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdn2.smoot.apple.com")
	if(dnsDomainIs(host, "cdn2.smoot.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "configuration.apple.com")
	if(dnsDomainIs(host, "configuration.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kt-prod.ess.apple.com")
	if(dnsDomainIs(host, "kt-prod.ess.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "stats.gc.apple.com")
	if(dnsDomainIs(host, "stats.gc.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sylvan.apple.com")
	if(dnsDomainIs(host, "sylvan.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fpinit.itunes.apple.com")
	if(dnsDomainIs(host, "fpinit.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "updates.cdn-apple.com")
	if(dnsDomainIs(host, "updates.cdn-apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdsassets.apple.com")
	if(dnsDomainIs(host, "cdsassets.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "acris.nyc.gov")
	if(dnsDomainIs(host, "acris.nyc.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "courts.state.ny.us")
	if(dnsDomainIs(host, "courts.state.ny.us")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nycourts.gov")
	if(dnsDomainIs(host, "nycourts.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "covidsafe.gov.au")
	if(dnsDomainIs(host, "covidsafe.gov.au")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "arrivecan.cbsa-asfc.cloud-nuage.canada.ca")
	if(dnsDomainIs(host, "arrivecan.cbsa-asfc.cloud-nuage.canada.ca")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "israel-entry.piba.gov.il")
	if(dnsDomainIs(host, "israel-entry.piba.gov.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "applications.labor.ny.gov")
	if(dnsDomainIs(host, "applications.labor.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "apps.labor.ny.gov")
	if(dnsDomainIs(host, "apps.labor.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "unemployment.labor.ny.gov")
	if(dnsDomainIs(host, "unemployment.labor.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "my.ny.gov")
	if(dnsDomainIs(host, "my.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "static-assets.ny.gov")
	if(dnsDomainIs(host, "static-assets.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "labor.ny.gov")
	if(dnsDomainIs(host, "labor.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "dol.ny.gov")
	if(dnsDomainIs(host, "dol.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "login.ny.gov")
	if(dnsDomainIs(host, "login.ny.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "acris.nyc.gov")
	if(dnsDomainIs(host, "acris.nyc.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "covid19relief1.sba.gov")
	if(dnsDomainIs(host, "covid19relief1.sba.gov")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "t-mobile.com")
	if(dnsDomainIs(host, "t-mobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mms.att.net")
	if(dnsDomainIs(host, "mms.att.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bell.ca")
	if(dnsDomainIs(host, "bell.ca")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "swisscom.ch")
	if(dnsDomainIs(host, "swisscom.ch")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mms.fido.ca")
	if(dnsDomainIs(host, "mms.fido.ca")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mms.gprs.rogers.com")
	if(dnsDomainIs(host, "mms.gprs.rogers.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mmsmvno.com")
	if(dnsDomainIs(host, "mmsmvno.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sprintpcs.com")
	if(dnsDomainIs(host, "sprintpcs.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sprint.com")
	if(dnsDomainIs(host, "sprint.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "icloud-content.com")
	if(dnsDomainIs(host, "icloud-content.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myvodafone.com.au")
	if(dnsDomainIs(host, "myvodafone.com.au")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vodafone.com.au")
	if(dnsDomainIs(host, "vodafone.com.au")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "xcap.private.att.net")
	if(dnsDomainIs(host, "xcap.private.att.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cingular.com")
	if(dnsDomainIs(host, "cingular.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "H20Mobileweb.com")
	if(dnsDomainIs(host, "H20Mobileweb.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobile.att.net")
	if(dnsDomainIs(host, "mobile.att.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "verizonwireless.com")
	if(dnsDomainIs(host, "verizonwireless.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rami-levy.co.il")
	if(dnsDomainIs(host, "rami-levy.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bezeqint.net")
	if(dnsDomainIs(host, "bezeqint.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bezeq.co.il")
	if(dnsDomainIs(host, "bezeq.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "hotmobile.co.il")
	if(dnsDomainIs(host, "hotmobile.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "rimon.net.il")
	if(dnsDomainIs(host, "rimon.net.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"ivzwentp.tracfone.com")
	if(dnsDomainIs(host,"ivzwentp.tracfone.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"verizon.com")
	if(dnsDomainIs(host,"verizon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"verizon.net")
	if(dnsDomainIs(host,"verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"fast.t-mobile.com")
	if(dnsDomainIs(host,"fast.t-mobile.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"verizon.inq.com")
	if(dnsDomainIs(host,"verizon.inq.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"vzwcorp.com")
	if(dnsDomainIs(host,"vzwcorp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"vzwc.com")
	if(dnsDomainIs(host,"vzwc.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vodafone.co.uk")
	if(dnsDomainIs(host, "vodafone.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vodafoneuk.demdex.net")
	if(dnsDomainIs(host, "vodafoneuk.demdex.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vodafoneuk.digital.nuance.com")
	if(dnsDomainIs(host, "vodafoneuk.digital.nuance.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vodafoneuk.nanorep.co")
	if(dnsDomainIs(host, "vodafoneuk.nanorep.co")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cw.net")
	if(dnsDomainIs(host, "cw.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "40.ip-51-89-148.eu")
	if(dnsDomainIs(host, "40.ip-51-89-148.eu")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smp-device-content.apple.com")
	if(dnsDomainIs(host, "smp-device-content.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ft.newyorklife.com")
	if(dnsDomainIs(host, "ft.newyorklife.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "waze.com")
	if(dnsDomainIs(host, "waze.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "waze.co.il")
	if(dnsDomainIs(host, "waze.co.il")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bugsense.com")
	if(dnsDomainIs(host, "bugsense.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "samsungipolis.com")
	if(dnsDomainIs(host, "samsungipolis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chase.com")
	if(dnsDomainIs(host, "chase.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chasecdn.com")
	if(dnsDomainIs(host, "chasecdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "venmo.com")
	if(dnsDomainIs(host, "venmo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "loopnet.com")
	if(dnsDomainIs(host, "loopnet.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "itau.com.ar")
	if(dnsDomainIs(host, "itau.com.ar")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "itau.com.br")
	if(dnsDomainIs(host, "itau.com.br")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "birdapp.com")
	if(dnsDomainIs(host, "birdapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tradestation.com")
	if(dnsDomainIs(host, "tradestation.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "thalesgroup.com")
	if(dnsDomainIs(host, "thalesgroup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ipass.com")
	if(dnsDomainIs(host, "ipass.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "panasonic.aero")
	if(dnsDomainIs(host, "panasonic.aero")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "btwifi.com")
	if(dnsDomainIs(host, "btwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "btwifi.co.uk")
	if(dnsDomainIs(host, "btwifi.co.uk")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guce.yahoo.com")
	if(dnsDomainIs(host, "guce.yahoo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skyfii.io")
	if(dnsDomainIs(host, "skyfii.io")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "gocloudwifi.com")
	if(dnsDomainIs(host, "gocloudwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "simservs.ngn.etsi.org")
	if(dnsDomainIs(host, "simservs.ngn.etsi.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "classroom.google.com")
	if(dnsDomainIs(host, "classroom.google.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "widget-mediator.zopim.com")
	if(dnsDomainIs(host, "widget-mediator.zopim.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "edmodo.com")
	if(dnsDomainIs(host, "edmodo.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nissanusa.com")
	if(dnsDomainIs(host, "nissanusa.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nissanfinance.com")
	if(dnsDomainIs(host, "nissanfinance.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nimbusnetworks.com")
	if(dnsDomainIs(host, "nimbusnetworks.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "hoteles.login.gocloud1.com")
	if(dnsDomainIs(host, "hoteles.login.gocloud1.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "chownow.com")
	if(dnsDomainIs(host, "chownow.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tmodns.net")
	if(dnsDomainIs(host, "tmodns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "snap.safetyaccess.com")
	if(dnsDomainIs(host, "snap.safetyaccess.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "selectnetworx.com")
	if(dnsDomainIs(host, "selectnetworx.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "socialwifi.com")
	if(dnsDomainIs(host, "socialwifi.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "computop-paygate.com")
	if(dnsDomainIs(host, "computop-paygate.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "profile.localytics.com")
	if(dnsDomainIs(host, "profile.localytics.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mobilenetworkscoring-pa.googleapis.com")
	if(dnsDomainIs(host, "mobilenetworkscoring-pa.googleapis.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "spcsdns.net")
	if(dnsDomainIs(host, "spcsdns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ipayment.com")
	if(dnsDomainIs(host, "ipayment.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifipass.org")
	if(dnsDomainIs(host, "wifipass.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "usaepay.com")
	if(dnsDomainIs(host, "usaepay.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "duosecurity.com")
	if(dnsDomainIs(host, "duosecurity.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paycomonline.net")
	if(dnsDomainIs(host, "paycomonline.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "api.sunocopay.com")
	if(dnsDomainIs(host, "api.sunocopay.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "directbuilding.noip.me")
	if(dnsDomainIs(host, "directbuilding.noip.me")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "opensignal.com")
	if(dnsDomainIs(host, "opensignal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "alpinedvr.dwddns.net")
	if(dnsDomainIs(host, "alpinedvr.dwddns.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "globalsuite.net")
	if(dnsDomainIs(host, "globalsuite.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "wifilauncher.com")
	if(dnsDomainIs(host, "wifilauncher.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "swissconnectforguests.com")
	if(dnsDomainIs(host, "swissconnectforguests.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "domaincontrol.com")
	if(dnsDomainIs(host, "domaincontrol.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "symcb.com")
	if(dnsDomainIs(host, "symcb.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "yeled.org")
	if(dnsDomainIs(host, "yeled.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "speedpay.com")
	if(dnsDomainIs(host, "speedpay.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "herokuapp.com")
	if(dnsDomainIs(host, "herokuapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "misameach.org")
	if(dnsDomainIs(host, "misameach.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "bt.com")
	if(dnsDomainIs(host, "bt.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, ".fon.com")
	if(dnsDomainIs(host, ".fon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "btfonpurchases.com")
	if(dnsDomainIs(host, "btfonpurchases.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "charityextra.com")
	if(dnsDomainIs(host, "charityextra.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "guestwifi.core.nyp.org")
	if(dnsDomainIs(host, "guestwifi.core.nyp.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "splash.gozonehotspot.com")
	if(dnsDomainIs(host, "splash.gozonehotspot.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"stopthebrokerban.com")
	if(dnsDomainIs(host,"stopthebrokerban.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"nysaba.app.sparkinfluence.net")
	if(dnsDomainIs(host,"nysaba.app.sparkinfluence.net")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"69.42.172.65","255.255.255.0")
	if(isInNet(dnsResolve(host),"69.42.172.65","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"69.42.173.65","255.255.255.0")
	if(isInNet(dnsResolve(host),"69.42.173.65","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host),"69.42.167.210","255.255.255.0")
	if(isInNet(dnsResolve(host),"69.42.167.210","255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"telebroad.com")
	if(dnsDomainIs(host,"telebroad.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, ".ring.com")
	if(dnsDomainIs(host, ".ring.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "paypal.com")
	if(dnsDomainIs(host, "paypal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "incoming.yahoo.verizon.net")
	if(dnsDomainIs(host, "incoming.yahoo.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outgoing.yahoo.verizon.net")
	if(dnsDomainIs(host, "outgoing.yahoo.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "incoming.verizon.net")
	if(dnsDomainIs(host, "incoming.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "outgoing.verizon.net")
	if(dnsDomainIs(host, "outgoing.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "smtp.verizon.net")
	if(dnsDomainIs(host, "smtp.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "pop.verizon.net")
	if(dnsDomainIs(host, "pop.verizon.net")) return "DIRECT";

	//FROM RULE: BYPASS:shExpMatch(url, "vimeo.com/_unblock_ratelimit")
	if(shExpMatch(url, "vimeo.com/_unblock_ratelimit")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "signal.org")
	if(dnsDomainIs(host, "signal.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "textsecure-service.whispersystems.org")
	if(dnsDomainIs(host, "textsecure-service.whispersystems.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tdcardservices.com")
	if(dnsDomainIs(host, "tdcardservices.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tdwealth.netxinvestor.com")
	if(dnsDomainIs(host, "tdwealth.netxinvestor.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "netxselect.com")
	if(dnsDomainIs(host, "netxselect.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "sso-idp.tdsecurities.com")
	if(dnsDomainIs(host, "sso-idp.tdsecurities.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "centresuite.com")
	if(dnsDomainIs(host, "centresuite.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "visaprepaidprocessing.com")
	if(dnsDomainIs(host, "visaprepaidprocessing.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "clientpoint.fisglobal.com")
	if(dnsDomainIs(host, "clientpoint.fisglobal.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "returns.narvar.com")
	if(dnsDomainIs(host, "returns.narvar.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "skypeassets.com")
	if(dnsDomainIs(host, "skypeassets.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vtext.com")
	if(dnsDomainIs(host, "vtext.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzwpix.com")
	if(dnsDomainIs(host, "vzwpix.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "myvzw.com")
	if(dnsDomainIs(host, "myvzw.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mypixmessages.com")
	if(dnsDomainIs(host, "mypixmessages.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzwdm.com")
	if(dnsDomainIs(host, "vzwdm.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vZims.com")
	if(dnsDomainIs(host, "vZims.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "vzmessages.com")
	if(dnsDomainIs(host, "vzmessages.com")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "69.78.224.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "69.78.224.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "69.78.64.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "69.78.64.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "69.78.0.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "69.78.0.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "64.152.68.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "64.152.68.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "66.174.92.13", "255.255.0.0")
	if(isInNet(dnsResolve(host), "66.174.92.13", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "162.115.18.210", "255.255.0.0")
	if(isInNet(dnsResolve(host), "162.115.18.210", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "162.115.210.210", "255.255.0.0")
	if(isInNet(dnsResolve(host), "162.115.210.210", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "137.188.82.210", "255.255.0.0")
	if(isInNet(dnsResolve(host), "137.188.82.210", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "162.115.216.30", "255.255.0.0")
	if(isInNet(dnsResolve(host), "162.115.216.30", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "162.115.24.30", "255.255.0.0")
	if(isInNet(dnsResolve(host), "162.115.24.30", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "192.16.31.69", "255.255.0.0")
	if(isInNet(dnsResolve(host), "192.16.31.69", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "204.153.144.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "204.153.144.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "194.213.11.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "194.213.11.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "194.50.183.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "194.50.183.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "91.204.216.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "91.204.216.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "62.85.251.0", "255.255.0.0")
	if(isInNet(dnsResolve(host), "62.85.251.0", "255.255.0.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "35.160.118.79", "255.255.255.0")
	if(isInNet(dnsResolve(host), "35.160.118.79", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:isInNet(dnsResolve(host), "52.0.44.141", "255.255.255.0")
	if(isInNet(dnsResolve(host), "52.0.44.141", "255.255.255.0")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"toasttab.com")
	if(dnsDomainIs(host,"toasttab.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ocsp.apple.com")
	if(dnsDomainIs(host, "ocsp.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "push.apple.com")
	if(dnsDomainIs(host, "push.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "barcoder-cyf.herokuapp.com")
	if(dnsDomainIs(host, "barcoder-cyf.herokuapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "tiqcdn.com")
	if(dnsDomainIs(host, "tiqcdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "hubspot.com")
	if(dnsDomainIs(host, "hubspot.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "omtrdc.net")
	if(dnsDomainIs(host, "omtrdc.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "yeshivaworlds3.b-cdn.net")
	if(dnsDomainIs(host, "yeshivaworlds3.b-cdn.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cdn.shira24videos.com")
	if(dnsDomainIs(host, "cdn.shira24videos.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "files.dryveup.com")
	if(dnsDomainIs(host, "files.dryveup.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "cloudfront.yiddish24.com")
	if(dnsDomainIs(host, "cloudfront.yiddish24.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "iosapps.itunes.apple.com")
	if(dnsDomainIs(host, "iosapps.itunes.apple.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "edge.24liveblog.com")
	if(dnsDomainIs(host, "edge.24liveblog.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "m4.technicalmoon.com")
	if(dnsDomainIs(host, "m4.technicalmoon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "kids.pbs-video.pbs.org")
	if(dnsDomainIs(host, "kids.pbs-video.pbs.org")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mp-lura-live.akamaized.net")
	if(dnsDomainIs(host, "mp-lura-live.akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mp-lura-live.fsy.nfl.com")
	if(dnsDomainIs(host, "mp-lura-live.fsy.nfl.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "mako-streaming.akamaized.net")
	if(dnsDomainIs(host, "mako-streaming.akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "foxvideo-sports-cf.video.fox")
	if(dnsDomainIs(host, "foxvideo-sports-cf.video.fox")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "foxvideo-sports.akamaized.net")
	if(dnsDomainIs(host, "foxvideo-sports.akamaized.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "r.dofustream.com")
	if(dnsDomainIs(host, "r.dofustream.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "fls-na.amazon.com")
	if(dnsDomainIs(host, "fls-na.amazon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "unagi.amazon.com")
	if(dnsDomainIs(host, "unagi.amazon.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "ccmdls.adobe.com")
	if(dnsDomainIs(host, "ccmdls.adobe.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "nikevideo.nike.com")
	if(dnsDomainIs(host, "nikevideo.nike.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "lkwd-daf-yomi.nyc3.cdn.digitaloceanspaces.com")
	if(dnsDomainIs(host, "lkwd-daf-yomi.nyc3.cdn.digitaloceanspaces.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "oraysa-files.s3.us-east-2.amazonaws.com")
	if(dnsDomainIs(host, "oraysa-files.s3.us-east-2.amazonaws.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "omtmapupdate.garmin.com")
	if(dnsDomainIs(host, "omtmapupdate.garmin.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host, "torahcdn.net")
	if(dnsDomainIs(host, "torahcdn.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"redsky.target.com")
	if(dnsDomainIs(host,"redsky.target.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"usea1-nessat.sentinelone.net")
	if(dnsDomainIs(host,"usea1-nessat.sentinelone.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"euce1-109.sentinelone.net")
	if(dnsDomainIs(host,"euce1-109.sentinelone.net")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"dishwireless.asapp.com")
	if(dnsDomainIs(host,"dishwireless.asapp.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"api.fedex.com")
	if(dnsDomainIs(host,"api.fedex.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"*api.jcpenney.com")
	if(dnsDomainIs(host,"*api.jcpenney.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"*my.sharepoint.com")
	if(dnsDomainIs(host,"*my.sharepoint.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"vod-adaptive-ak.vimeocdn.com")
	if(dnsDomainIs(host,"vod-adaptive-ak.vimeocdn.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"www.qantas.com")
	if(dnsDomainIs(host,"www.qantas.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"www.godaddy.com")
	if(dnsDomainIs(host,"www.godaddy.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"sofiagray.com")
	if(dnsDomainIs(host,"sofiagray.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"ecp.yusercontent.com")
	if(dnsDomainIs(host,"ecp.yusercontent.com")) return "DIRECT";

	//FROM RULE: BYPASS:dnsDomainIs(host,"www.teamlifeline.org")
	if(dnsDomainIs(host,"www.teamlifeline.org")) return "DIRECT";

	//FROM RULE: PROXY:true
	if(true) return "PROXY us-ios.gentechsolution.com:41653;";

}
