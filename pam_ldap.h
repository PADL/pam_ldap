
typedef struct
{
        /* space delimited list of servers */
        char *plc_host;
        /* port, expected to be common to all servers */
        int plc_port;
        /* base DN, eg. dc=gnu,dc=org */
        char *plc_base;
        /* scope for searches */
        int plc_scope;
        char *plc_binddn;
        char *plc_bindpw;        
        char *plc_sslpath;
        char *plc_filter;
        /* defaults to uid */
        char *plc_attr;
        /* search for password policy */
        int plc_getpolicy;
} pam_ldap_config;

typedef struct
{
    int passwordChange;
    int passwordCheckSyntax;
    int passwordMinLength;
    int passwordExp;
    int passwordMaxAge;
    int passwordWarning;
    int passwordKeepHistory;
    int passwordInHistory;
    int passwordLockout;
    int passwordMaxFailure;
    int passwordUnlock;
    int passwordLockoutDuration;
    int passwordResetDuration;
} pam_ldap_password_policy;

typedef struct {
    int passwordExpirationTime;
    int passwordExpWarned;
    int passwordRetryCount;
    int retryCountResetTime;
    int accountUnlockTime;
} pam_ldap_password_info;

typedef struct
{
    LDAP *pls_ld;
    int pls_ldapversion;
    pam_ldap_config *pls_conf;
} pam_ldap_session;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

