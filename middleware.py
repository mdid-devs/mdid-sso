"""
Single Sign On Middleware fork for mdid3
"""
import string
from random import Random
import logging

import ldap
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.models import User as User
from django.contrib.sites.models import Site

import sys
import time
from rooibos.auth import login as login
from rooibos.auth.ldapauth import LdapAuthenticationBackend
from util import generate_sso_token


class rooibos_LDAP(LdapAuthenticationBackend):
    @classmethod
    def ldap_user_lookup(cls, token_id):
        """
        lookup LDAP user and return the attributes needed for account creation
        This method is called by rooibos_LDAP.new_account_from_ldap()
        :param token_id (username from sso token)
        :return: None or user attributes
        """
        logging.debug('SSO: create new account for %s in %s' % (token_id, cls))
        try:
            for ldap_auth in settings.LDAP_AUTH:
                username_lookup = token_id.strip()
                l = ldap.initialize(ldap_auth['uri'])
                l.protocol_version = ldap_auth['version']
                for option, value in ldap_auth['options'].iteritems():
                    l.set_option(getattr(ldap, option), value)

                # for cases where a bind user is needed (most places)
                if ldap_auth.get('bind_user'):
                    #bind credential for lookup
                    l.simple_bind(ldap_auth['bind_user'],
                                  ldap_auth.get('bind_password'))
                    #search for user to confirm
                result = l.search_s(ldap_auth['base'],
                                    ldap_auth['scope'], '%s=%s' % (ldap_auth['cn'], username_lookup),
                                    ldap_auth.get('attributes', 'attributes'))
                logging.debug('SSO.new_ldap: search result for %s:  %s? ' % (username_lookup, result,))
                # check that result isn't empty
                if len(result) != 1:
                    logging.debug('SSO: ldap search for %s failed, returned: %s' % (username_lookup, result))
                    return None
                elif len(result) != 1:
                    continue

                # TODO: is result[0][1] specific to the tested implementation? Can it be made more generic?
                attributes = result[0][1]

                # conform attributes to expected format
                for attr in ldap_auth['attributes']:
                    if attr in attributes:
                        if not type(attributes[attr]) in (tuple, list):
                            attributes[attr] = (attributes[attr],)
                    else:
                        attributes[attr] = []
                logging.debug('SSO: ldap_user_lookup returning %s' % attributes)
                return attributes
        except Exception, e:
            logging.debug('SSO: ldap_user_lookup for %s failed, returned: %s' % (token_id, e))
            return None

    @classmethod
    def new_account_from_ldap(cls, token_id):
        """
        Create a new account from username_lookup using LDAP information
        :param token_id: username_lookup from sso token
        :return: User object or None
        """
        attributes = cls.ldap_user_lookup(token_id)

        for ldap_auth in settings.LDAP_AUTH:
            try:
                user = User.objects.get(username=token_id)
                if user:
                    return user

            except User.DoesNotExist:
                # logging.debug('SSO: backend: %s %s ' % (backend, ldap_get))
                try:
                    # this password is meant to never be used, so it will be something like
                    # 'AToWJ ZLDI\x0cUxiRhaDVYsHyN26jwmPfIQtHXbFSA'
                    password = ' '.join(Random().sample(string.letters +
                                                        string.digits +
                                                        string.uppercase +
                                                        string.whitespace, 40))

                    user = User(username=token_id, password=password)
                    user.first_name = ' '.join(attributes[ldap_auth['firstname']])
                    user.last_name = ' '.join(attributes[ldap_auth['lastname']])
                    user.email = attributes[ldap_auth['email']][0]
                    user.save()
                    logging.debug('SSO: created user %s (%s %s (%s) from LDAP' % (user.id,
                                                                                  user.first_name,
                                                                                  user.last_name,
                                                                                  user.email))
                    return user

                except Exception as e:
                    logging.debug('SSO: Exception %s' % e)
                    logging.debug('SSO: new_account_from_ldap failed due to', sys.exc_info()[0])

                    return None


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

    def redirect_to_top(self):
        #redirect_to = settings.LOGIN_REDIRECT_URL
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    def process_request(self, request):
        # SESSION_KEY = '_auth_user_id'
        # BACKEND_SESSION_KEY = '_auth_user_backend'
        token = request.GET.get('token', False)
        token_id = request.GET.get('id', False)
        timestamp = request.GET.get('timestamp', False)
        if token and token_id and timestamp:
            logging.debug('SSO: user %s login attempt via SSO in with timestamp %s and token %s \n' % (
                token_id, timestamp, token))
            if self.check_token(token, token_id, timestamp):
                # everything passed, authenticate user
                logging.debug('SSO: user %s token and timestamp pass \n' % token_id)
                logging.debug('SSO: Attempting to authenticate as %s \n' % token_id)
                try:
                    user = self.authenticate(token_id)
                except Exception as e:
                    logging.debug('SSO: user %s does not exist, trying to create \n' % token_id)
                    rooibos_LDAP.new_account_from_ldap(token_id)

                if user.username == token_id:
                    try:
                        # THIS WAS THE KEY TO IT WORKING
                        user.backend = settings.SSO_BACKEND
                        login(request, user)
                        logging.debug('SSO: process_request - user.backend = %s' % user.backend)
                        #return None
                        #logging.debug(user.last_login)
                        # logging.debug(request.session['_auth_user_id'])
                        # logging.debug(request.session['_auth_user_backend'])
                    except Exception:
                        raise

    def check_token(self, token, token_id, timestamp):
        """
        checks the token based on token_id, timestamp, and sso secret
        """
        toke_check = generate_sso_token(token_id, timestamp)

        if time.time() - float(timestamp) <= self.timeout:
            #logging.debug('SSO: checking login token \n\t%s \n\tvs check token \n\t%s \n' % (token, toke_check))
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

        user = None

        for backend in get_backends():
            if backend:
                try:
                    user = User.objects.get(username=token_id)
                    #logging.debug('SSO.authenticate: username %s authenticated with %s' % (token_id, backend))

                except User.DoesNotExist:
                    logging.debug('SSO: username %s does not exist in %s' % (token_id, backend.__class__.__name__))
                    try:
                        user = rooibos_LDAP.new_account_from_ldap(token_id=token_id)
                    except Exception, e:
                        logging.debug('SSO.authenticate: '
                                      'SSO.rooibos_LDAP.new_account_from_ldap failed for %s ...\n %s' % (token_id, e))

        logging.debug('SSO.authenticate: returning user %s ' % user)
        return user

    def process_response(self, request, response):
        """ takes the response output and replaces urls """
        try:
            if request.user.is_authenticated():
                try:
                    if settings.SSO_DOMAINS:
                        response.content = self.replace_domain_urls(response.content, settings.SSO_DOMAINS)
                    else:
                        pass
                except Exception as e:
                    logging.debug('SSO.process_response_subtry : %s ' % e)
                    pass
        except Exception as e:
            # in case request.user doesn't exist
            #logging.debug('user %s does not exist' % request.GET.get('id', False))
            logging.debug('SSO.process_response : %s ' % e)
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