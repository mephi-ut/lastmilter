
// === Includes ===
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <syslog.h>
#include <search.h>
#include <sqlite3.h>
#include <pthread.h>

#define MAX_RECIPIENTS 		100
#define MAX_KNOWNSENDERS	(1 << 20)

// === Global definitions ===
static sqlite3 *db = NULL;

enum flags {
	FLAG_EMPTY		= 0x0000,
	FLAG_CHECK_NEWSENDER	= 0x0001,
	FLAG_CHECK_SPF		= 0x0002,
	FLAG_CHECK_DKIM		= 0x0004,
	FLAG_CHECK_REGEX	= 0x0008,
	FLAG_DRY		= 0x0100,
	FLAG_DONTADDHEADER	= 0x0200,
};
typedef enum flags flags_t;

enum dkim_status {
	DKIM_NONE = 0,
	DKIM_PASS = 1,
	DKIM_FAIL = 2,
};
typedef enum dkim_status dkim_status_t;

enum spf_status {
	SPF_UNKNOWN = 0,
	SPF_NONE,
	SPF_PASS,
	SPF_NEUTRAL,
	SPF_SOFTFAIL,
	SPF_FAIL,
};
typedef enum spf_status spf_status_t;

enum regex_status {
	REGEX_UNKNOWN = 0,
	REGEX_ACCEPT,
	REGEX_NONE,
	REGEX_TEMPFAIL,
	REGEX_QUARANTINE,
	REGEX_REJECT,
	REGEX_DISCARD,
};
typedef enum regex_status regex_status_t;

static flags_t flags = FLAG_EMPTY;

static int todomains_limit = 4;
static int threshold_badscore = 30;

static int badscore_domainlimit    = 10;
static int badscore_newsender      = 10;
static int badscore_htmlmail       = 10;
static int badscore_blacklisted    = 20;
static int badscore_frommismatched = 10;
static int badscore_spf_none       =  5;
static int badscore_spf_softfail   = 15;
static int badscore_spf_fail       = 25;
static int badscore_dkim_none      =  5;
static int badscore_dkim_fail      = 20;
static int badscore_noto           = 25;

static int badscore_regex_accept     = -30;
static int badscore_regex_none       =   0;
static int badscore_regex_tempfail   =   5;
static int badscore_regex_quarantine =  10;
static int badscore_regex_reject     =  20;
static int badscore_regex_discard    =  30;

struct private {
	char			*mailfrom;
	char 			 mailfrom_isnew;
	char			 sender_blacklisted;
	char			 from_mismatched;
	char			 body_hashtml;
	spf_status_t		 spf;
	dkim_status_t		 dkim;
	regex_status_t		 regex;
	int 			 todomains;
	struct hsearch_data 	 todomain_htab;
	char			*todomain[MAX_RECIPIENTS];

	int			 badscore;
};
typedef struct private private_t;

static struct hsearch_data mailfrom_htab={0};
static pthread_mutex_t mailfrom_mutex;

static int   mailfroms = 0;
static char *mailfrom[MAX_KNOWNSENDERS];

#define R(a) (flags&FLAG_DRY ? SMFIS_CONTINUE : a)

// === SQLite3 routines ===

void mailfrom_htab_add(const char const *mailfrom_in) {
	char *mailfrom_cur = strdup(mailfrom_in);
	mailfrom[mailfroms++] = mailfrom_cur;

	ENTRY entry, *ret;
	entry.key  = (char *)mailfrom_cur;
	entry.data = (void *)1;
	if(!hsearch_r(entry, ENTER, &ret, &mailfrom_htab)) {
		syslog(LOG_CRIT, "mailfrom_htab_add(): Cannot insert new \"MAIL FROM\" entry (too small MAX_KNOWNSENDERS?): %s (errno: %i). Exit.\n",
			strerror(errno), errno);
		exit(EX_SOFTWARE);
	}
	syslog(LOG_NOTICE, "mailfrom_htab_add(): \"%s\".\n", mailfrom_cur);

	return;
}

static int mailfrom_get_callback(void *nullarg, int argc, char **argv, char **colname) {
	int i;
	i=0;
	while(i<argc) {
		if(!strcmp(colname[i], "mailfrom"))
			mailfrom_htab_add(argv[i]);
		i++;
	}
	return 0;
}

void mailfrom_get() {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;

	if(!hcreate_r(MAX_KNOWNSENDERS, &mailfrom_htab)) {
		syslog(LOG_CRIT, "mailfrom_get(): Failure on hcreate_r(): %s (errno: %i). Exit.\n", strerror(errno), errno);
		exit(EX_SOFTWARE);
	}

	sprintf(query, "DELETE FROM tocheckmilter_mailfrom WHERE dom < strftime('%%s', 'now')-(3600*24*365)");
	rc = sqlite3_exec(db, query, (int (*)(void *, int,  char **, char **))mailfrom_get_callback, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot delete expired \"MAIL FROM\" from history in DB: %s. Exit.\n", errmsg);
		exit(EX_SOFTWARE);
	}

	sprintf(query, "SELECT mailfrom FROM tocheckmilter_mailfrom");
	rc = sqlite3_exec(db, query, (int (*)(void *, int,  char **, char **))mailfrom_get_callback, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot get valid \"MAIL FROM\" history from DB: %s. Exit.\n", errmsg);
		exit(EX_SOFTWARE);
	}
	return;
}

void mailfrom_upd(const char const *mailfrom) {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;
	sprintf(query, "UPDATE tocheckmilter_mailfrom SET count=count+1, dom=CURRENT_TIMESTAMP WHERE mailfrom=\"%s\"", 
		mailfrom);

	pthread_mutex_lock(&mailfrom_mutex);

	rc = sqlite3_exec(db, query, NULL, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot update \"MAIL FROM\" in history in DB: %s. Ignoring.\n", errmsg);
//		exit(EX_SOFTWARE);
	}

	pthread_mutex_unlock(&mailfrom_mutex);

	return;
}

void mailfrom_add(const char const *mailfrom) {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;
	sprintf(query, "INSERT INTO tocheckmilter_mailfrom VALUES(\"%s\", CURRENT_TIMESTAMP, 1)", 
		mailfrom);

	pthread_mutex_lock(&mailfrom_mutex);

	rc = sqlite3_exec(db, query, NULL, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot insert new \"MAIL FROM\" into history in DB: %s. Ignoring.\n", errmsg);
//		exit(EX_SOFTWARE);
	}

	mailfrom_htab_add(mailfrom);

	pthread_mutex_unlock(&mailfrom_mutex);

	return;
}

int mailfrom_chk(const char const *mailfrom) {
	pthread_mutex_lock(&mailfrom_mutex);

	ENTRY entry, *ret;
	entry.key  = (char *)mailfrom;
	entry.data = (void *)1;
	hsearch_r(entry, FIND, &ret, &mailfrom_htab);

	pthread_mutex_unlock(&mailfrom_mutex);

	if(ret != NULL)
		return 1;

	syslog(LOG_NOTICE, "mailfrom_chk(): Cannot find \"%s\".\n", mailfrom);
	return 0;
}

void mailfrom_free() {
	hdestroy_r(&mailfrom_htab);

	while(mailfroms--)
		free(mailfrom[mailfroms]);
	return;
}

// === Code ===

extern sfsistat lastmilter_cleanup(SMFICTX *, bool);

sfsistat lastmilter_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	private_t *private_p = calloc(1, sizeof(private_t));
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "lastmilter_connect(): Cannot allocate memory. Exit.\n");
		exit(EX_SOFTWARE);
	}

	if(!hcreate_r(MAX_RECIPIENTS+2, &private_p->todomain_htab)) {
		syslog(LOG_NOTICE, "lastmilter_connect(): Failure on hcreate_r(). Exit.\n");
		exit(EX_SOFTWARE);
	}

	syslog(LOG_NOTICE, "lastmilter_connect(): Connection from: %s.\n", hostname);
	if (!strcmp(hostname, "lists.ut.mephi.ru")) {
		private_p->badscore = -20;
	}

	smfi_setpriv(ctx, private_p);

	return SMFIS_CONTINUE;
}

sfsistat lastmilter_helo(SMFICTX *ctx, char *helohost) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_envfrom(SMFICTX *ctx, char **argv) {

	if(argv[0] == NULL) {
		syslog(LOG_NOTICE, "%s: lastmilter_envfrom(): argv[0]==NULL. Sending TEMPFAIL.\n", smfi_getsymval(ctx, "i"));
		return R(SMFIS_TEMPFAIL);
	}
	if(*argv[0] == 0) {
		syslog(LOG_NOTICE, "%s: lastmilter_envfrom(): *argv[0]==0. Sending TEMPFAIL.\n", smfi_getsymval(ctx, "i"));
		return R(SMFIS_TEMPFAIL);
	}

	private_t *private_p = smfi_getpriv(ctx);

	private_p->mailfrom  = strdup(argv[0]);
	private_p->mailfrom_isnew = !mailfrom_chk(argv[0]);

	return SMFIS_CONTINUE;
}

sfsistat lastmilter_envrcpt(SMFICTX *ctx, char **argv) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_header(SMFICTX *ctx, char *headerf, char *_headerv) {
	if(!strcasecmp(headerf, "To") || !strcasecmp(headerf, "Cc")) {
		syslog(LOG_NOTICE, "%s: lastmilter_header(): \"%s\": \"%s\".\n", smfi_getsymval(ctx, "i"), headerf, _headerv);

		private_t *private_p = smfi_getpriv(ctx);
		if(private_p == NULL) {
			syslog(LOG_NOTICE, "%s: lastmilter_header(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
			return SMFIS_CONTINUE;
		}

		char *at_saveptr = NULL;
		char *headerv = strdup(_headerv);
		char *at = strtok_r(headerv, "@", &at_saveptr);	// Skipping the first part ["blah-blah@bleh-bleh, blah-blah@bleh-blah"]
								//                           _________
		do {
			at = strtok_r(NULL, "@", &at_saveptr);

			if(at == NULL)
				break;

			char *domainend_saveptr = NULL;
			strtok_r(&at[1], " \n\t)(<>@,;:\"/[]?=", &domainend_saveptr);
			char *domainend = strtok_r(NULL, " \n\t)(<>@,;:\"/[]?=", &domainend_saveptr);

			if(domainend == NULL)
				domainend = &at[strlen(at)];

			char *domain = malloc(domainend - at + 9);
			memcpy(domain, at, domainend-at);
			domain[domainend-at] = 0;

			syslog(LOG_NOTICE, "%s: lastmilter_header(): todomain: %s.\n", smfi_getsymval(ctx, "i"), domain);

			ENTRY entry, *ret;

			entry.key  = domain;
			entry.data = (void *)1;

			hsearch_r(entry, FIND, &ret, &private_p->todomain_htab);

			if(ret == NULL) {
				hsearch_r(entry, ENTER, &ret, &private_p->todomain_htab);
				private_p->todomain[private_p->todomains++] = domain;
			} else
				free(domain);

		} while(private_p->todomains < MAX_RECIPIENTS);
		free(headerv);
	} else

	// Blacklists
	if(!strcasecmp(headerf, "X-DNSBL-MILTER")) {
		private_t *private_p = smfi_getpriv(ctx);
		if(!strcasecmp(_headerv, "Blacklisted"))
			private_p->sender_blacklisted = 1;

		syslog(LOG_NOTICE, "%s: lastmilter_header(): Found DNSBL header value: %s. Blacklisted: %u.\n",
			smfi_getsymval(ctx, "i"), _headerv, private_p->sender_blacklisted);
	} else

	// MAILFROM !~ From
	if(!strcasecmp(headerf, "X-FromChk-Milter-MailFrom")) {
		private_t *private_p = smfi_getpriv(ctx);
		if(!strcasecmp(_headerv, "mismatch"))
			private_p->from_mismatched = 1;

		syslog(LOG_NOTICE, "%s: lastmilter_header(): Found FromChkMilter MailFrom header value: %s. Mismatched: %u.\n",
			smfi_getsymval(ctx, "i"), _headerv, private_p->from_mismatched);
	} else

	// DKIM
	if(!strcasecmp(headerf, "Authentication-Results")) {
		private_t *private_p = smfi_getpriv(ctx);
		if (private_p->dkim == DKIM_NONE) {
			if(strstr(_headerv, "dkim=fail"))
				private_p->dkim = DKIM_FAIL;
			else
			if(strstr(_headerv, "dkim=pass"))
				private_p->dkim = DKIM_PASS;

			syslog(LOG_NOTICE, "%s: lastmilter_header(): Found DKIM header value: %s. status: %u.\n",
				smfi_getsymval(ctx, "i"), _headerv, private_p->dkim);
		}
	} else

	// SPF
	if(!strcasecmp(headerf, "Received-SPF")) {
		private_t *private_p = smfi_getpriv(ctx);
		if(!strncasecmp(_headerv, "none", 4))
			private_p->spf = SPF_NONE;
		else
		if(!strncasecmp(_headerv, "fail", 4))
			private_p->spf = SPF_FAIL;
		else
		if(!strncasecmp(_headerv, "softfail", 8))
			private_p->spf = SPF_SOFTFAIL;
		else
		if(!strncasecmp(_headerv, "permerror", 9))
			private_p->spf = SPF_SOFTFAIL;
		else
		if(!strncasecmp(_headerv, "neutral", 7))
			private_p->spf = SPF_PASS;
		else
		if(!strncasecmp(_headerv, "pass", 4))
			private_p->spf = SPF_PASS;
		else
			private_p->spf = SPF_PASS;

		syslog(LOG_NOTICE, "%s: lastmilter_header(): Found SPF header value: %s. status: %u.\n",
			smfi_getsymval(ctx, "i"), _headerv, private_p->spf);
	}

	// regex
	if(!strcasecmp(headerf, "X-MILTER-REGEX")) {
		private_t *private_p = smfi_getpriv(ctx);
		if(!strncasecmp(_headerv, "Accept", 6))
			private_p->regex = REGEX_ACCEPT;
		else
		if(!strncasecmp(_headerv, "Tempfail", 8))
			private_p->regex = REGEX_TEMPFAIL;
		else
		if(!strncasecmp(_headerv, "Quarantine", 10))
			private_p->regex = REGEX_QUARANTINE;
		else
		if(!strncasecmp(_headerv, "Reject", 6))
			private_p->regex = REGEX_REJECT;
		else
		if(!strncasecmp(_headerv, "Discard", 7))
			private_p->regex = REGEX_DISCARD;
		else
			private_p->regex = REGEX_NONE;

		syslog(LOG_NOTICE, "%s: lastmilter_header(): Found X-MILTER-REGEX header value: %s. status: %u.\n",
			smfi_getsymval(ctx, "i"), _headerv, private_p->regex);
	}

	return SMFIS_CONTINUE;
}

sfsistat lastmilter_eoh(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
	private_t *private_p = smfi_getpriv(ctx);
	if(strstr((char *)bodyp, "\nContent-Type: text/html")) {
		private_p->body_hashtml = 1;
		syslog(LOG_NOTICE, "%s: lastmilter_body(): Seems, that here's HTML included.\n", smfi_getsymval(ctx, "i"));
	}
	return SMFIS_CONTINUE;
}

static inline int lastmilter_eom_ok(SMFICTX *ctx, private_t *private_p) {
	if(!(flags & FLAG_DONTADDHEADER)) {
		char buf[BUFSIZ];
		sprintf(buf, "%i", private_p->badscore);
		smfi_addheader(ctx, "X-LastMilter", "passed");
		smfi_addheader(ctx, "X-LastMilter-Score", buf);
	}

	if(private_p->mailfrom_isnew)
		mailfrom_add(private_p->mailfrom);
	else
		mailfrom_upd(private_p->mailfrom);
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_eom(SMFICTX *ctx) {
	private_t *private_p = smfi_getpriv(ctx);
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "%s: lastmilter_eom(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
		return SMFIS_CONTINUE;
	}

	int badscore=private_p->badscore;

	if(flags & FLAG_CHECK_NEWSENDER)
		if(private_p->mailfrom_isnew)
			badscore += badscore_newsender;

	if(private_p->body_hashtml)
		badscore += badscore_htmlmail;

	if(private_p->sender_blacklisted)
		badscore += badscore_blacklisted;

	if(private_p->from_mismatched)
		badscore += badscore_frommismatched;

	if(private_p->todomains > todomains_limit) {
		syslog(LOG_NOTICE, "%s: lastmilter_eom(): Too many domains in \"To\" field: %u > %u.\n", 
			smfi_getsymval(ctx, "i"), private_p->todomains, todomains_limit);
		badscore += badscore_domainlimit;
	}

	if(private_p->todomains == 0) {
		syslog(LOG_NOTICE, "%s: lastmilter_eom(): No \"To\". Adding %u to the bad-score.\n", 
			smfi_getsymval(ctx, "i"), badscore_noto);
		badscore += badscore_noto;
	}

	syslog(LOG_NOTICE, "%s: lastmilter_eom(): Base checks complete. Total: %i.\n",
		smfi_getsymval(ctx, "i"), badscore);

	if(flags&FLAG_CHECK_DKIM) {
		switch(private_p->dkim) {
			case DKIM_NONE:
				badscore += badscore_dkim_none;
				break;
			case DKIM_FAIL:
				badscore += badscore_dkim_fail;
				break;
			case DKIM_PASS:
			default:
				break;
		}
	}

	syslog(LOG_NOTICE, "%s: lastmilter_eom(): DKIM complete. Total: %i.\n",
		smfi_getsymval(ctx, "i"), badscore);

	if(flags&FLAG_CHECK_SPF) {
		switch(private_p->spf) {
			case SPF_NONE:
				badscore += badscore_spf_none;
				break;
			case SPF_SOFTFAIL:
				badscore += badscore_spf_softfail;
				break;
			case SPF_FAIL:
				badscore += badscore_spf_fail;
				break;
			case SPF_PASS:
			case SPF_UNKNOWN:
			default:
				break;
		}
	}

	syslog(LOG_NOTICE, "%s: lastmilter_eom(): SPF complete. Total: %i.\n",
		smfi_getsymval(ctx, "i"), badscore);

	if(flags&FLAG_CHECK_REGEX) {
		switch(private_p->regex) {
			case REGEX_ACCEPT:
				badscore += badscore_regex_accept;
				break;
			case REGEX_NONE:
				badscore += badscore_regex_none;
				break;
			case REGEX_TEMPFAIL:
				badscore += badscore_regex_tempfail;
				break;
			case REGEX_QUARANTINE:
				badscore += badscore_regex_quarantine;
				break;
			case REGEX_REJECT:
				badscore += badscore_regex_reject;
				break;
			case REGEX_DISCARD:
				badscore += badscore_regex_discard;
				break;
			default:
				break;
		}
	}

	syslog(LOG_NOTICE, "%s: lastmilter_eom(): regex complete. Total: %i.\n",
		smfi_getsymval(ctx, "i"), badscore);

	private_p->badscore = badscore;

	syslog(LOG_NOTICE, "%s: lastmilter_eom(): Total: mailfrom_isnew == %u; to_domains == %u, body_hashtml == %u, sender_blacklisted == %u, from_mismatched == %u, spf == %u, dkim == %u. Bad-score == %i.%s\n",
		smfi_getsymval(ctx, "i"), private_p->mailfrom_isnew, private_p->todomains, private_p->body_hashtml, private_p->sender_blacklisted, private_p->from_mismatched, private_p->spf, private_p->dkim, badscore, (badscore > threshold_badscore) ? " Sending REJECT." : "");

	if(badscore > threshold_badscore)
		return R(SMFIS_REJECT);
	else
		return lastmilter_eom_ok(ctx, private_p);
}

sfsistat lastmilter_abort(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_close(SMFICTX *ctx) {
	private_t *private_p = smfi_getpriv(ctx);
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "%s: lastmilter_close(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
		return SMFIS_CONTINUE;
	}

	hdestroy_r(&private_p->todomain_htab);
	while(private_p->todomains--) {
		free(private_p->todomain[private_p->todomains]);
	}
	free(private_p->mailfrom);
	free(private_p);
	smfi_setpriv(ctx, NULL);

	return SMFIS_CONTINUE;
}

sfsistat lastmilter_unknown(SMFICTX *ctx, const char *cmd) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_data(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat lastmilter_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
	SMFICTX *ctx;
	unsigned long f0;
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned long *pf0;
	unsigned long *pf1;
	unsigned long *pf2;
	unsigned long *pf3;
{
	return SMFIS_ALL_OPTS;
}

static void usage(const char *path) {
	fprintf(stderr, "Usage: %s -p socket-addr [-t timeout] [-L domain limit] [-T bad-score threshold] [-H html bad-score] [-B blacklist bad-score] [-M MAIL FROM <> From mismatch bad-score] [-N /path/to/sqlite/db] [-HdBQS]\n",
		path);
}

int main(int argc, char *argv[]) {
	struct smfiDesc mailfilterdesc = {
		"TheLastMilter",		// filter name
		SMFI_VERSION,			// version code -- do not change
		SMFIF_ADDHDRS|SMFIF_ADDRCPT,	// flags
		lastmilter_connect,		// connection info filter
		lastmilter_helo,		// SMTP HELO command filter
		lastmilter_envfrom,		// envelope sender filter
		lastmilter_envrcpt,		// envelope recipient filter
		lastmilter_header,		// header filter
		lastmilter_eoh,			// end of header
		lastmilter_body,		// body block filter
		lastmilter_eom,			// end of message
		lastmilter_abort,		// message aborted
		lastmilter_close,		// connection cleanup
		lastmilter_unknown,		// unknown SMTP commands
		lastmilter_data,		// DATA command
		lastmilter_negotiate		// Once, at the start of each SMTP connection
	};

	char setconn = 0;
	int c;
	const char *args = "p:t:hHdN:A:BMOQSDRT:l:";
	extern char *optarg;
	// Process command line options
	while ((c = getopt(argc, argv, args)) != -1) {
		switch (c) {
			case 'p':
				if (optarg == NULL || *optarg == '\0')
				{
					(void)fprintf(stderr, "Illegal conn: %s\n",
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_setconn(optarg) == MI_FAILURE)
				{
					(void)fprintf(stderr,
						"smfi_setconn failed\n");
					exit(EX_SOFTWARE);
				}

				if (strncasecmp(optarg, "unix:", 5) == 0)
					unlink(optarg + 5);
				else if (strncasecmp(optarg, "local:", 6) == 0)
					unlink(optarg + 6);
				setconn = 1;
				break;
			case 't':
				if (optarg == NULL || *optarg == '\0') {
					(void)fprintf(stderr, "Illegal timeout: %s\n", 
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
					(void)fprintf(stderr,
						"smfi_settimeout failed\n");
					exit(EX_SOFTWARE);
				}
				break;
			case 'd':
				flags |= FLAG_DRY;
				break;
			case 'H':
				badscore_htmlmail       = atoi(optarg);
				break;
			case 'B':
				badscore_blacklisted    = atoi(optarg);
				break;
			case 'M':
				badscore_frommismatched = atoi(optarg);
				break;
			case 'Q':
				flags |= FLAG_DONTADDHEADER;
				break;
			case 'S':
				flags |= FLAG_CHECK_SPF;
				break;
			case 'D':
				flags |= FLAG_CHECK_DKIM;
				break;
			case 'R':
				flags |= FLAG_CHECK_REGEX;
				break;
			case 'T':
				threshold_badscore = atoi(optarg);
				break;
			case 'N':
                                // Openning the DB
				if(sqlite3_open_v2(optarg, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
//                              if(sqlite3_open(optarg, &db)) {
					fprintf(stderr, "Cannot open SQLite3 DB-file \"%s\"\n", optarg);
					exit(EX_SOFTWARE);
				}

				// Checking it's validness. Fixing if required.
				int rc;
				sqlite3_stmt *stmt = NULL;
				rc = sqlite3_prepare_v2(db, "SELECT mailfrom, dom, count FROM tocheckmilter_mailfrom LIMIT 1", -1, &stmt, NULL);
				if(rc != SQLITE_OK) {
					// Fixing the table "statmilter_stats"
					fprintf(stderr, "Invalid DB file \"%s\". Recreating table \"tocheckmilter_mailfrom\" in it.\n", optarg);
					sqlite3_exec(db, "DROP TABLE tocheckmilter_mailfrom", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE TABLE tocheckmilter_mailfrom (mailfrom VARCHAR(255), dom timestamp DEFAULT CURRENT_TIMESTAMP, count integer(8) DEFAULT 0)", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE UNIQUE INDEX mailfrom_idx ON tocheckmilter_mailfrom (mailfrom)", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE INDEX dom_idx ON tocheckmilter_mailfrom (dom)", NULL, NULL, NULL);
				}
				sqlite3_finalize(stmt);
				flags |= FLAG_CHECK_NEWSENDER;
				break;
			case 'l':
				todomains_limit = atoi(optarg);
				break;
			case 'A':
				badscore_noto = atoi(optarg);
				break;
			case 'h':
			default:
				usage(argv[0]);
				exit(EX_USAGE);
		}
	}

	if(!setconn) {
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}
	if(smfi_register(mailfilterdesc) == MI_FAILURE) {
		fprintf(stderr, "smfi_register() failed\n");
		exit(EX_UNAVAILABLE);
	}
	if(pthread_mutex_init(&mailfrom_mutex, NULL)) {
		fprintf(stderr, "pthread_mutex_init() failed\n");
		exit(EX_SOFTWARE);
	}
	openlog(NULL, LOG_PID, LOG_MAIL);
	mailfrom_get();
	int ret = smfi_main();
	sqlite3_close(db);
	closelog();
	mailfrom_free();
	pthread_mutex_destroy(&mailfrom_mutex);
	return ret;
}

