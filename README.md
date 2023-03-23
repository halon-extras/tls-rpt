# tls-rpt

Pre-delivery

```
	// MTA-STS
	$mtasts = mta_sts($message["recipientaddress"]["domain"]);
	if (is_array($mtasts))
	{
		$context["sts"] = $mtasts;
		if ($mtasts["error"])
		{
			$tlsrpt = tls_rpt([], $message, $mtasts);
			$logtlsrpt = [
				"url" => "https://user:pass@host:9200",
				"path" => "/tlsrpt-alias/_doc",
				"httpoptions" => [
					"timeout" => 10,
					// "background" => true,
					// "background_hash" => hash($message["id"]["transaction"]),
					// "background_retry_count" => 3,
					"tls_default_ca" => true,
					"headers" => ["Content-Type: application/json"]
				]
			];

			$logdata = [
				"timestamp" => round(time() * 1000),
				"transactionid" => $message["id"]["transaction"],
				...$tlsrpt
			];
			http($logtlsrpt["url"].$logtlsrpt["path"], $logtlsrpt["httpoptions"], [], json_encode($logdata));

			Queue(["reason" => "Bad MTA-STS: ". $mtasts["error"]]);
		}
		if ($mtasts["policy"]["mode"] == "enforce")
		{
			$tryargs += [
				"mx_include" => $mtasts["policy"]["mx"],
				"tls" => "dane_fallback_require_verify",
				"tls_sni" => true,
				"tls_verify_host" => true,
				"tls_default_ca" => true,
				"tls_protocols" => "!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
			];
		}
	}
	Try($tryargs);
```

Post-delivery

```
if ($arguments["attempt"] and tls_rpt_fetch_dnstxt($message["recipientaddress"]["domain"]))
{
	$tlsrpt = tls_rpt($arguments["attempt"]["connection"], $message, $context["sts"]);
	$logtlsrpt = [
		"url" => "https://user:pass@host:9200",
		"path" => "/tlsrpt-alias/_doc",
		"httpoptions" => [
			"timeout" => 10,
			// "background" => true,
			// "background_hash" => hash($message["id"]["transaction"]),
			// "background_retry_count" => 3,
			"tls_default_ca" => true,
			"headers" => ["Content-Type: application/json"]
		]
	];

	$logdata = [
		"timestamp" => round(time() * 1000),
		"transactionid" => $message["id"]["transaction"],
		...$tlsrpt
	];
	http($logtlsrpt["url"].$logtlsrpt["path"], $logtlsrpt["httpoptions"], [], json_encode($logdata));
}
```
