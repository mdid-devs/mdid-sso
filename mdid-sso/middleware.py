"""
Single Sign On Middleware
"""
import string
import time
from django.http import HttpResponseRedirect
from django.conf import settings
from rooibos.auth import login
# rooibos.auth.ldapauth import LdapAuthenticationBackend as ldap_get
from rooibos.auth.baseauth import BaseAuthenticationBackend as Base_auth
from django.contrib.auth.models import User as User
from django.contrib.sites.models import Site
import ldap
import logging

from util import generate_sso_token


class SingleSignOnMiddleware(object):
    """
    checks for sso token and logs user in
    checks for external urls to change
    """

    def __init__(self):
        # noinspection PyBroadException
        try:
            self.timeout = settings.SSO_TIMEOUT
        except:
            self.timeout = 1
        try:
            self.protocol = settings.SSO_PROTOCOL
        except:
            self.protocol = 'http://'

    def process_request(self, request):
        token = request.GET.get('token', False)
        token_id = request.GET.get('id', False)
        timestamp = request.GET.get('timestamp', False)
        if token and token_id and timestamp:
            logging.debug(
                'SSO: user %s login attempt via SSO in with timestamp %s and token %s \n' % (
                    token_id, timestamp, token))
            if self.check_token(token, token_id, timestamp):
                # everything passed, authenticate user
                logging.debug('SSO: user %s token and timestamp pass \n' % token_id)
                #
                logging.debug('SSO: Attempting to authenticate as %s \n' % token_id)

                user = self.authenticate(token_id)
                try:
                    login(request, user)
                except NotImplementedError:
                    logging.info('SSO: ==+== login fail - NotImplementedError - redirecting to login page===== \n')
                    raise
                except:
                    logging.info('SSO: ====== login fail %s redirect to login page================ ' % user)
                    redirect_to = settings.LOGIN_REDIRECT_URL
                    return HttpResponseRedirect(redirect_to)
            else:
                logging.debug('SSO: user %s login fail with token %s' % (token_id, token, ))
        return None

    def check_token(self, token, token_id, timestamp):
        """
        checks the token based on token_id, timestamp, and sso secret
        """
        toke_check = generate_sso_token(token_id, timestamp)

        if time.time() - float(timestamp) <= self.timeout:
            logging.debug('SSO: checking login token \n\t%s \n\tvs check token \n\t%s \n' % (token, toke_check))
            return token == toke_check
        else:
            logging.debug('SSO: timestamp %s is out of range with system time (%s) \n' % (timestamp, time.time()))
        return False

    def authenticate(self, token_id):
        """
        go through the backends to find the user
        same as django.contrib.auth.authenticate but doesn't need a password
        :return user
        """
        from django.contrib.auth import get_backends

        for backend in get_backends():
            try:
                #user = backend.get_user(token_id)
                #logging.debug(backend.get_user(token_id))
                logging.debug('SSO.authenticate: username %s ' % token_id)
                user = User.objects.get(username=token_id)

            except User.DoesNotExist:
                logging.debug('SSO: username %s does not exist in %s' % (token_id, backend.__class__.__name__))
                user = self.new_account_from_ldap(token_id)
                return user
                # except:
            #     # didn't work, try the next one.
            #     logging.debug('backend %s - %s' % (backend.__module__, backend.__class__.__name__))
            #     continue

            if user.username != token_id:
                print 'SSO: %s != %s' % (user.username, token_id)
                user = self.new_account_from_ldap(token_id)
                continue
            # Annotate the user object with the path of the backend.
            else:
                user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
                #logging.debug('user.backend: %s' % user.backend)
                return user

    def process_response(self, request, response):
        """ takes the response output and replaces urls """
        try:
            if request.user.is_authenticated():
                try:
                    domains = settings.SSO_DOMAINS
                    if domains:
                        response.content = self.replace_domain_urls(response.content, domains)
                    else:
                        pass
                except:
                    pass
        except:
            # in case request.user doesn't exist
            logging.debug('user %s does not exist' % request.GET.get('id', False))
            pass
        return response

    def replace_domain_urls(self, content, domains):
        """
        Replaces urls for domains specified and replaces them with 
        a url to the sso view that will generate a token and redirect
        """
        current_domain = Site.objects.get_current().domain
        for domain in domains:
            if not domain.startswith('http://') and not domain.startswith('https://'):
                domain = 'http://' + domain
            content = string.replace(content, domain, '%s%s/sso/?next=%s' % (
                self.protocol,
                current_domain,
                domain
            ))
        return content

    def new_account_from_ldap(self, token_id):
        """
        Create a new account from username_lookup using LDAP information
        :param token_id: username_lookup from sso token
        :return: User object or None
        """

        for backend in settings.AUTHENTICATION_BACKENDS:

            if backend == 'rooibos.auth.ldapauth.LdapAuthenticationBackend':
                logging.debug('SSO: create new account for %s in %s' % (token_id, backend))
                try:
                    for ldap_auth in settings.LDAP_AUTH:
                        #ldap_get.authenticate(id,password=None)
                        username_lookup = token_id.strip()
                        l = ldap.initialize(ldap_auth['uri'])
                        l.protocol_version = ldap_auth['version']
                        for option, value in ldap_auth['options'].iteritems():
                            l.set_option(getattr(ldap, option), value)

                        if ldap_auth.get('bind_user'):
                        #bind credential for lookup
                            l.simple_bind(ldap_auth['bind_user'],
                                          ldap_auth.get('bind_password'))
                            #search for user to confirm
                        result = l.search_s(ldap_auth['base'],
                                            ldap_auth['scope'], '%s=%s' % (ldap_auth['cn'], username_lookup),
                                            ldap_auth.get('attributes', 'attributes'))
                        logging.debug('SSO.new_ldap: search result for %s:  %s? ' % (username_lookup, result,))
                        if len(result) != 1:
                            logging.debug('SSO: ldap search for %s failed, returned: %s' % (username_lookup, result))
                            return None
                        elif len(result) != 1:
                            continue
                        attributes = result[0][1]
                        for attr in ldap_auth['attributes']:
                            if attributes.has_key(attr):
                                if not type(attributes[attr]) in (tuple, list):
                                    attributes[attr] = (attributes[attr],)
                            else:
                                attributes[attr] = []
                        try:
                            user = User.objects.get(username=username_lookup)
                        except User.DoesNotExist:
                            user = backend._create_user(backend, username_lookup,
                                                        None,
                                                        ' '.join(attributes[ldap_auth['firstname']]),
                                                        ' '.join(attributes[ldap_auth['lastname']]),
                                                        attributes[ldap_auth['email']][0])
                        return user
                except:  # this shouldn't be so vague, but I'm not sure what to check for
                    if username_lookup and backend:
                        logging.debug('SSO: User %s was not able to be created from LDAP (%s). What now?' % (
                            username_lookup, backend))
                    raise

        logging.debug('SSO: new_account_from_ldap for %s failed' % token_id)
        return None
