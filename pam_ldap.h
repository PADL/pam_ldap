
typedef struct
{
        /* space delimited list of servers */
        char *host;
        /* port, expected to be common to all servers */
        int port;
        /* base DN, eg. dc=gnu,dc=org */
        char *base;
        /* scope for searches */
        int scope;
        char *binddn;
        char *bindpw;        
        char *sslpath;
        char *filter;
        /* defaults to uid */
        char *attr;
        /* search for password policy */
        int getpolicy;
} pam_ldap_config;

typedef struct
{
    int password_change;
    int password_check_syntax;
    int password_min_length;
    int password_exp;
    int password_max_age;
    int password_warning;
    int password_keep_history;
    int password_in_history;
    int password_lockout;
    int password_max_failure;
    int password_unlock;
    int password_lockout_duration;
    int password_reset_duration;
} pam_ldap_password_policy;

typedef struct {
    char *dn;
    int password_expiration_time;
    int password_exp_warned;
    int password_retry_count;
    int retry_count_reset_time;
    int account_unlock_time;
} pam_ldap_user_info;

typedef struct
{
    LDAP *ld;
    int ldap_version;
    int bound_as_user;
    pam_ldap_config *conf;
    pam_ldap_user_info *info;
} pam_ldap_session;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

