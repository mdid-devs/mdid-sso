# mdid-SSO
# add these to your settings_local.py or wherever you prefer

SSO_TIMEOUT = 10
SSO_PROTOCOL = 'https://'

# domains for which sso keys are generated
# the SSO_DOMAINS setting is used to rewrite specific outgoing links (see original readme below)
# if uninterested, set to False to avoid errors in your logs

SSO_DOMAINS = False

# this should be changed prior to deployment
# https://docs.djangoproject.com/en/dev/ref/settings/#secret-key
SSO_SECRET = 'zp*+x2)p6q)ft6han8rn8717d#h#2hk$4s-2f*8n*1fw&04h+j'


SSO_CAPS = True

# currently this only supports LDAP, but hopefully in the future others will be supported
SSO_BACKEND = 'rooibos.auth.ldapauth.LdapAuthenticationBackend'


INSTALLED_APPS = (
    'rooibos.apps.mdid-sso',
)

MIDDLEWARE_CLASSES = (
    'rooibos.apps.mdid-sso.middleware.SingleSignOnMiddleware',
)
