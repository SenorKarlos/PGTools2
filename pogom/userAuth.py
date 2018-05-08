#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import json
import requests
import urllib
from cachetools import TTLCache
from datetime import datetime, timedelta
from timeit import default_timer

from flask import abort, redirect
from requests.exceptions import HTTPError

from security import AESCipher

log = logging.getLogger(__name__)


class DiscordAPI():
    ENDPOINT = 'https://discordapp.com/api/v6'

    def __init__(self, args):
        self.client_id = args.user_auth_client_id
        self.client_secret = args.user_auth_client_secret
        self.aes_cipher = AESCipher(args.user_auth_secret_key)
        self.auth_cache = TTLCache(maxsize=10000, ttl=300)

        self.block_concurrent = args.user_auth_block_concurrent
        if args.user_auth_block_concurrent:
            hold_time = args.user_auth_block_concurrent * 3600
        else:
            hold_time = 3600
        self.blacklist = TTLCache(maxsize=10000, ttl=hold_time)

        self.hostname = args.host
        if args.external_hostname:
            self.hostname = args.external_hostname

        self.redirect_uri = '{}/auth_callback'.format(self.hostname)
        self.validity = args.user_auth_validity * 3600

        self.guild_required = args.user_auth_guild_required
        self.guild_invite_link = args.user_auth_guild_invite
        self.role_required = args.user_auth_role_required
        self.role_invite_link = args.user_auth_role_invite
        self.bot_token = args.user_auth_bot_token

        self.guild_roles = self.get_guild_role_names()

    def post_request(self, uri, data, headers):
        url = '{}/{}'.format(self.ENDPOINT, uri)
        r = requests.post(url, data, headers)
        try:
            r.raise_for_status()
            return r.json()
        except HTTPError:
            log.error('Failed POST request to Discord API at %s: %s - %s.',
                      url, r.status_code, r.text)

        return None

    def get_request(self, uri, headers, params=None):
        url = '{}/{}'.format(self.ENDPOINT, uri)
        r = requests.get(url, params, headers=headers)
        try:
            r.raise_for_status()
            return r.json()
        except HTTPError:
            log.error('Failed GET request to Discord API at %s: %s - %s.',
                      url, r.status_code, r.text)

        return None

    # https://discordapp.com/developers/docs/topics/oauth2#authorization-code-grant-access-token-response
    def exchange_code(self, code):
        uri = '/oauth2/token'
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        return self.post_request(uri, data, headers)

    def refresh_token(self, refresh_token):
        uri = '/oauth2/token'
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'code': refresh_token,
            'redirect_uri': self.redirect_uri
        }
        headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        }

        return self.post_request(uri, data, headers)

    def validate_auth(self, session, response):
        result = {'auth': False, 'url': None}

        access_token = response.get('access_token', None)
        if not access_token:
            log.error('Invalid OAuth response from Discord API.')
            return result

        user_guilds = self.get_user_guilds(access_token)
        if user_guilds is None:
            log.error('Unable to retrieve user guilds from Discord API.')
            return result
        elif user_guilds:
            guild_ids = [x['id'] for x in user_guilds]
            response['guilds'] = guild_ids

        user_data = self.get_user(access_token)
        if not user_data:
            log.error('Unable to retrieve user data from Discord API.')
            return result

        user_id = user_data['id']
        response['user_id'] = user_id
        response['username'] = user_data['username']

        guild_member = self.get_guild_member(self.guild_required, user_id)
        if not guild_member:
            log.error('Unable to retrieve user roles from Discord API.')
            return result

        role_ids = guild_member.get('roles', [])
        role_names = []
        for role_id in role_ids:
            role_name = self.guild_roles.get(role_id, None)
            if not role_name:
                log.error('Discord user role is not on guild roles.')
            else:
                role_names.append(role_name)

        response['roles'] = role_names
        log.debug('User %s has Discord guild roles: %s',
                  response['username'], response['roles'])

        # Check requirements.
        if not self.guild_required:
            result['auth'] = True
            return result

        if self.guild_required not in response['guilds']:
            log.debug('User %s has not joined the required Discord guild.',
                      response['username'])
            result['url'] = self.guild_invite_link
            return result

        if self.role_required:
            roles_found = []
            for role_required in self.role_required:
                if role_required in response['roles']:
                    roles_found.append(role_required)

            if not roles_found:
                log.debug('User %s lacks all of the %d required role(s).',
                          response['username'], len(self.role_required))
                result['url'] = self.role_invite_link
                return result

        # Configure user credentials expiration date.
        refresh_time = min(self.validity, response['expires_in'])
        session['refresh_date'] = (datetime.utcnow() +
                                   timedelta(seconds=refresh_time))

        # Encrypt and store user credentials on session cookie.
        response = json.dumps(response)
        session['user_auth'] = self.aes_cipher.encrypt(response)
        session['user_id'] = user_id

        result['auth'] = True
        return result

    def redirect_to_auth(self):
        redirect_uri = urllib.quote(self.redirect_uri)
        url = ('{}/oauth2/authorize?response_type=code&client_id={}&'
               'redirect_uri={}&scope=identify%20guilds').format(
                   self.ENDPOINT, self.client_id, redirect_uri)
        return redirect(url)

    # https://discordapp.com/developers/docs/topics/oauth2#authorization-code-grant
    def check_auth(self, session, user_agent, remote_addr):
        user_id = session.get('user_id')
        # Check if session is initialized.
        if not user_id:
            return self.redirect_to_auth()

        # Check if user ID is blacklisted.
        if self.blacklist.get(user_id):
            return abort(403)

        # Check if user credentials are cached.
        now = default_timer()
        cached = self.auth_cache.get(user_id)
        if cached:
            if not self.block_concurrent:
                return None

            # Monitor for concurrent logins.
            if (user_agent != cached['user_agent'] or
                    remote_addr != cached['remote_addr']):
                cached['changes'] += 1
                elapsed = now - cached['time']
                if elapsed > 60 and elapsed < 120 and cached['changes'] > 20:
                    log.warning('Detected concurrent accesses from user: %s',
                                user_id)
                    self.blacklist[user_id] = True
                    abort(403)
                cached['user_agent'] = user_agent
                cached['remote_addr'] = remote_addr

            return None

        try:
            # Decrypt and validate user credentials from session.
            decrypted = self.aes_cipher.decrypt(session['user_auth'])
            user_auth = json.loads(decrypted)

            if user_id == int(user_auth['user_id']):
                log.warning('Detected secure cookie tampering from user: %s',
                            user_id)
                session.clear()
                return self.redirect_to_auth()

            # Update cache.
            self.auth_cache[user_id] = {
                'user_agent': user_agent,
                'remote_addr': remote_addr,
                'time': now,
                'changes': 0
            }

            # Check if access token needs to be refreshed.
            if session['refresh_date'] < datetime.utcnow():
                response = self.refresh_token(user_auth['refresh_token'])
                session.clear()
                if not response:
                    log.error('Failed to refresh OAuth user authentication.')
                    return self.redirect_to_auth()

                valid = self.discord_api.validate_auth(session, response)
                if not valid['auth'] and not valid['url']:
                    return self.redirect_to_auth()
                elif not valid['auth']:
                    return redirect(valid['url'])

        except Exception as e:
            log.exception('Unable to verify user credentials: %s', e)
            return self.redirect_to_auth()

        return None

    # https://discordapp.com/developers/docs/resources/user#get-current-user-guilds
    def get_user_guilds(self, auth_token):
        endpoint = 'users/@me/guilds'
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/user#get-current-user
    # https://discordapp.com/developers/docs/resources/user#user-object
    def get_user(self, auth_token):
        endpoint = 'users/@me'
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/guild#get-guild-member
    # https://discordapp.com/developers/docs/resources/guild#guild-member-object
    def get_guild_member(self, guild_id, user_id):
        endpoint = 'guilds/{}/members/{}'.format(guild_id, user_id)
        headers = {
            'Authorization': 'Bot ' + self.bot_token
        }

        return self.get_request(endpoint, headers)

    # https://discordapp.com/developers/docs/resources/guild#get-guild-roles
    def get_guild_roles(self, guild_id):
        endpoint = 'guilds/{}/roles'.format(guild_id)
        headers = {
            'Authorization': 'Bot ' + self.bot_token
        }

        return self.get_request(endpoint, headers)

    # Translate role IDs to names.
    # https://discordapp.com/developers/docs/topics/permissions#role-object
    def get_guild_role_names(self):
        roles = {}
        guild_roles = self.get_guild_roles(self.guild_required)
        if not guild_roles:
            log.error('Unable to retrieve guild roles from Discord API.')
            return False

        for role in guild_roles:
            # Strip non-ascii characters from role name.
            stripped = (c for c in role['name'] if 0 < ord(c) < 127)
            role_name = ''.join(stripped)
            roles[role['id']] = role_name

        log.debug('Retrieved Discord guild roles: %s', roles)

        return roles
