
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
        /* require pamSecurityObject mixin */
        char *plc_objectclass;
        /* defaults to uid */
        char *plc_attr;
} pam_ldap_config;

typedef struct
{
    LDAP *pls_ld;
    int pls_ldapversion;
    pam_ldap_config *pls_conf;
} pam_ldap_session;

#define MAX_PASSWD_TRIES 3 
#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
