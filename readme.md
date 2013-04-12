#mdid-sso

###Single-signon to and from MDID3

TBD: MDID3 specific documentation.

Notes: Currently only the rooibos.auth.ldapauth.LdapAuthenticationBackend is supported, but it shouldn't be too much work to extend this to your local environment (please submit extensions back!)

__________

This is a fork of django-sso by pyro & namwood (http://codespatter.com/)

From the original readme at https://code.google.com/p/django-sso/


django-sso will allow your django application to accept single sign on links from other applications and authenticate users. It is also capable of creating links to other applications that use SSO links.

Add sso to your python path, INSTALLED_APPS, and middleware. The middleware needs to be after Session Middleware

    'sso.middleware.SingleSignOnMiddleware',

SSO_SECRET is a required setting. You can use it like the following or set your own.

    SSO_SECRET = SECRET_KEY


If you will be creating sso links with your django app, this is required.

    url(r'^sso/$', 'sso.views.sso', name="sso"),

With that you can create links with the following in your templates

    {% url sso %}?next=http://ivylees.com

That will create a url like

    http://ivylees.com/?id=123&timestamp=1234&token=12345

If you want to automatically replace all links to another domain, add them to this tuple. All of the following types of urls will work.

    SSO_DOMAINS = (
        'ivylees.com/user/',
        'presskitn.com',
        'http://codespatter.com',
    )
