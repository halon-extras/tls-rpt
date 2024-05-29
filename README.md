# SMTP TLS Reporting

This project implements SMTP TLS reporting (rfc8460). It supports both MTA-STS (rfc8461) and DANE (rfc7672). The reporting data is collected from the Pre- and Post-delivery hook and is stored in an Elastic database.
The data is fetch and processed by a service written in node.js. Reports can be sent using both SMTP and HTTP.

## Reporting service

The reporting service should be installed on a single server.

## MTA installation

On all MTA instances, the ``tls-rpt.hsl`` file should be added to the configuration and imported in the pre- and post delivery hook.

### Pre-delivery

The following code should be added to the pre-delivery hook.

```
import { tls_rpt_fetch_dnstxt, tls_rpt } from "file:tls-rpt.hsl";

// MTA-STS
$mtasts = mta_sts($message["recipientaddress"]["domain"]);
if (is_array($mtasts))
{
	if ($mtasts["error"])
	{
		if (tls_rpt_fetch_dnstxt($message["recipientaddress"]["domain"]))
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
		}

		Queue(["reason" => "Bad MTA-STS: ". $mtasts["error"]]);
	}
	$context["sts"] = $mtasts;
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

### Post-delivery

The following code should be added to the post-delivery hook.

```
import { tls_rpt_fetch_dnstxt, tls_rpt } from "file:tls-rpt.hsl";

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
