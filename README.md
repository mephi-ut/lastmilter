lastmilter
==========

This milter have get score based on:
 - Other milters results
 - HTML-letter or not
 - Unknown sender (never been met before)
 - Domain limit exhaustion in "To" field

And then mail will be rejected or accepted based on this score.

Any questions?
 - IRC: ircs://irc.campus.mephi.ru/#mephi,xai,xaionaro
 - email: <dyokunev@ut.mephi.ru> 0x8E30679C


options
-------

 - -p /path/to/unix/socket - path to unix socket to communicate with MTA.
 - -t timeout - timeout in seconds of communicating with MTA.
 - -l limit - limit of domains in "To" field
[bad-score: less or equal: 0; greater: 10]
 - -H score - score to add to "bad-score" if letter is HTML-like
(with "\nContent-Type: text/html" in body) [default: 10]
 - -N /path/to/db - add 10 bad-score points if mail from new sender
(in "MAIL FROM"). "/path/to/db" will be used to save SQLite3 DB with
senders table.
 - -d - dry run (don't reject mail)
 - -M score - score to add to "bad-score" in case of unsimilar "MAIL FROM" and
"From" (similarity status is detected by "X-FromChk-Milter-MailFrom" header
value left by [fromcheckmilter](https://github.com/mephi-ut/fromcheckmilter "fromcheckmilter"))
[default: 10]
 - -B score - score to add to "bad-score" if sender is blacklisted
(blacklisting status is detected by "X-DNSBL-MILTER" header value
left by [dnsbl-milter](https://github.com/hloeung/dnsbl-milter "dnsbl-milter")) [default: 10]
 - -S - check SPF header "Received-SPF" [bad-score: passed: 0; none: 5;
softfail: 10; fail: 20]
 - -T threshold - total "bad-score" threshold for passing mail [default: 20]
 - -h - help


example
-------

    lastmilter_header(): todomain: ukr.net.
    lastmilter_header(): todomain: mtu-net.ru.
    lastmilter_header(): todomain: bigmir.net.
    lastmilter_header(): todomain: xxxxx.xx.
    lastmilter_header(): Found DNSBL header value: Blacklisted. Blacklisted: 1.
    lastmilter_header(): Found FromChkMilter MailFrom header value: passed. Mismatched: 0.
    lastmilter_body(): Seems, that here's HTML included.
    lastmilter_eom(): Too many domains in "To" field: 4 > 3. Sending SMFIS_REJECT. lastmilter_eom(): Total: mailfrom_isnew == 1; to_domains == 4, body_hashtml == 1, sender_blacklisted == 1, from_mismatched == 0, spf == 0. Bad-score == 40.
    milter-reject: END-OF-MESSAGE from frontend02n.mail.kz[92.46.53.17]: 5.7.1 Command rejected; from=<ssk2000@mail.kz> to=<xxxxxx@xxxxx.xx> proto=ESMTP helo=<mail.kz>
