#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
import urllib
import datetime
import json
import time

from flask import redirect
from requests.exceptions import HTTPError
from rm_crypto import RmCrypto

from auth_base import AuthBase

class AuthDiscord(AuthBase):

    def __init__(self, args, url_root):
        self.log = logging.getLogger(__name__)
        self.auth_service = args.user_auth_service
        self.host = args.uas_host_override
        if not self.host:
            self.host = url_root
        self.key = args.secret_encryption_key
        self.invite_uri = args.uas_discord_guild_invite
        self.discord_client_id = args.uas_client_id
        self.discord_client_secret = args.uas_client_secret

        self.discord_bot_token = args.uas_discord_bot_token
        self.required_guilds = args.uas_discord_required_guilds
        self.required_roles = args.uas_discord_required_roles
        self.retrieval_period = int(args.uas_retrieval_period)

    def to_sensitive(self, sens_obj):
        plain = json.dumps(sens_obj, ensure_ascii=False)

        encText = RmCrypto.encrypt(self.key, plain)
        return encText

    def from_sensitive(self, stored):
        plain = RmCrypto.decrypt(self.key, stored)

        retrieveObject = json.loads(plain)
        return retrieveObject

    def check_auth(self, req, session):
        if self.auth_service == "Discord":
            #check if previous auth is present and valid
            auth_tuple = self.valid_session_client_auth(req, session)
            if auth_tuple[0]:
                #self.log.debug(session)
                auth_is_valid = False
                if auth_tuple[2] is None:
                    #got decrypted return value...
                    try:
                        auth_is_valid = self.check_guilds_and_roles(req, session, auth_tuple[1])
                    except TypeError:
                        self.clear_session_auth_values(session)
                else:
                    try:
                        auth_is_valid = self.check_guilds_and_roles(req, session, None)
                    except TypeError:
                        self.clear_session_auth_values(session)

                self.log.debug('Auth is valid')
                self.log.debug(auth_is_valid)
                if auth_is_valid:
                    self.log.debug('everything checks out, cya')
                    return None
                else:
                    #guilds or roles not valid.... TODO: check if no invite URI set
                    self.log.debug('Guilds or roles invalid')
                    if self.invite_uri:
                        return self.redirect_to_discord_guild_invite()
                    else:
                        return redirect('/', code=403)
            else:
                return self.redirect_client_to_auth()
        return None

    def redirect_client_to_auth(self):
        return redirect('https://discordapp.com/api/oauth2/authorize?client_id=' + self.discord_client_id + '&redirect_uri=' + urllib.quote(self.host + 'auth_callback') + '&response_type=code&scope=identify%20guilds')

    def redirect_to_discord_guild_invite(self):
        return redirect(self.invite_uri)

    #Retrieve access and refresh tokens from auth_callback's code and store it in session
    def exchange_code(self, code, session):
        data = {
          'client_id': self.discord_client_id,
          'client_secret': self.discord_client_secret,
          'grant_type': 'authorization_code',
          'code': code,
          'redirect_uri': self.host + "auth_callback"
        }
        headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(
            '%s/oauth2/token' % 'https://discordapp.com/api/v6', data, headers)
        try:
            r.raise_for_status()
        except HTTPError:
            self.log.debug('' + str(r.status_code) +
                      ' returned from OAuth attempt: ' +
                      r.text)
            return False
        jsonResponse = r.json()
        expires_in = jsonResponse.get('expires_in')
        expiration_date = time.time() + int(expires_in)
        jsonResponse['expires_at'] = expiration_date
        session['last_auth_check'] = time.time()
        return jsonResponse

    def refresh_tokens(self, session, plainAuthObject):
        data = {
          'client_id': self.discord_client_id,
          'client_secret': self.discord_client_secret,
          'grant_type': 'refresh_token',
          'code': plainAuthObject['refresh_token'],
          'redirect_uri': self.host + "auth_callback"
        }
        headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(
            '%s/oauth2/token' % 'https://discordapp.com/api/v6', data, headers)
        try:
            r.raise_for_status()
        except HTTPError:
            self.log.debug('' + str(r.status_code) +
                      ' returned from OAuth attempt: ' +
                      r.text)
            return False
        jsonResponse = r.json()
        expires_in = jsonResponse.get('expires_in')
        expiration_date = time.time() + int(expires_in)
        jsonResponse['expires_at'] = expiration_date
        session['last_auth_check'] = time.time()

        sensitiveData = to_sensitive(self.key, jsonResponse)
        session[self.auth_service + '_auth'] = sensitiveData
        return jsonResponse


    # Clears everything stored regarding auth
    def clear_session_auth_values(self, session):
        if session.get(self.auth_service +'_auth'):
            session.pop(self.auth_service +'_auth')
        if session.get('last_auth_check'):
            session.pop('last_auth_check')
        if session.get('last_requirements_retrieval'):
            session.pop('last_requirements_retrieval')
        if session.get('last_guild_ids'):
            session.pop('last_guild_ids')
        if session.get('last_guild_roles'):
            session.pop('last_guild_roles')
        if session.get('last_callback'):
            session.pop('last_callback')

    ################
    #Getters for values to check against
    ################

    #wrapper for getting guilds and roles
    def update_requirements(self, session, auth_token):
        self.log.debug("Retrieving guilds and roles")
        updateSuccess = True
        if self.required_guilds:
            self.log.debug("Getting guilds")
            updateSuccess = self.get_user_guilds(session, auth_token)
        if self.required_roles:
            updateSuccess = updateSuccess and self.get_user_guild_roles(session, auth_token)
        self.log.debug("Done retrieving guilds and roles")
        if updateSuccess:
            session['last_requirements_retrieval'] = time.time()
        return updateSuccess

    def get_user_guilds(self, session, auth_token):
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }
        r = requests.get('https://discordapp.com/api/v6/users/@me/guilds',
                         headers=headers)
        try:
            r.raise_for_status()
        except Exception:
            self.log.debug('' + str(r.status_code) +
                      ' returned from guild list attempt: ' +
                      r.text)
            return False
        session['last_guild_ids'] = r.json()
        self.log.debug('Guilds updated')
        return True

    def get_user_guild_roles(self, session, auth_token):
        headers = {
          'Authorization': 'Bearer ' + auth_token
        }
        r = requests.get('https://discordapp.com/api/v6/users/@me',
                         headers=headers)
        try:
            r.raise_for_status()
        except Exception:
            self.log.debug('' + str(r.status_code) +
                      ' returned from Discord @me attempt: ' +
                      r.text)
            return False
        user_id = r.json()['id']
        headers = {
          'Authorization': 'Bot ' + self.discord_bot_token
        }
        r = requests.get(
            'https://discordapp.com/api/v6/guilds/' +
            self.required_guilds.split(',')[0].strip() +
            '/members/' + user_id, headers=headers)
        try:
            r.raise_for_status()
        except Exception:
            self.log.debug('' + str(r.status_code) +
                      ' returned from Discord guild member attempt: ' +
                      r.text)
            return False
        session['last_guild_roles'] = r.json()['roles']
        self.log.debug('Roles updated')
        return True

    ################
    # Actual Auth check routine
    ################

    # Basic session auth check
    #Return (bool, None, encrypted Auth Object) or (Bool, decrypted_auth object, None)
    def valid_session_client_auth(self, req, session):
        last_auth_check = session.get('last_auth_check')
        if not last_auth_check:
            #self.log.debug('No previous auth in session')
            #no previous auth, let's have the user auth
            return (False, None, None)
        elif time.time() > (last_auth_check + 86400): #check the auth at least every 24hours
            return self.refresh_auth(req, session)
        else:
            return (True, None, session.get(self.auth_service +'_auth'))

    #returns bool
    #checks values stored in session
    #returns (Bool, decrypted AuthObject, None)
    def refresh_auth(self, req, session):
        sessionData = session.get(self.auth_service + '_auth')
        if sessionData:
            #we got data in the session, let's check it for validity
            try:
                plainData = self.from_sensitive(sessionData)
            except: #catch-all... bad practice, but if that's the case, we do not need any further treatment right now
                self.log.debug('Failed decrypting sessionData')
                self.clear_session_auth_values(session)
                return (False, None, None)

            if self.check_valid_discord_auth_object(plainData):
                #the sessions's token is still valid
                #TODO: consider refresh
                if plainData['expires_at'] - time.time() < 259200:
                    #auth is valid for less than another 3 days, refresh tokens
                    plainData = self.refresh_tokens(session, plainData)
                    if not plainData:
                        #could not refresh tokens
                        #TODO: consider some handling...
                        self.log.debug('Failed refreshing tokens')
                    else:
                        session[self.auth_service + '_auth'] = self.to_sensitive(plainData)
                else:
                    #for the moment, just use some processing power to transform plainData, we could modify it
                    #session[self.auth_service + '_auth'] = to_sensitive(plainData)
                    session['last_auth_check'] = time.time()
                return (True, plainData, None)
            else:
                #the session's token is invalid, bye
                #resp.set_cookie(self.auth_service +'_auth', '', expires=0)
                self.clear_session_auth_values(session)
                return (False, None, None)
        else:
            self.clear_session_auth_values(session)
            return (False, None, None)

    # Checks the auth-object's timestamp for validity
    def check_valid_discord_auth_object(self, auth_obj):
        #self.log.debug('Checking auth object')
        if not auth_obj:
            #self.log.debug('Auth object not valid')
            return False

        if auth_obj['expires_at'] < time.time():
            #self.log.debug('OAuth expired')
            return False
        else:
            #self.log.debug('OAuth valid until: ' + auth_obj['expires_at'])
            return True

    #############
    # Guild and Role checks
    #############

    #wrapper for check_guilds and check_roles
    def check_guilds_and_roles(self, req, session, plain_auth_obj):
        if self.required_guilds or self.required_roles:
            #self.log.debug('Checking guilds and roles')
            guilds_in_session = session.get('last_guild_ids')
            roles_in_session = session.get('last_guild_roles')
            last_requirements_retrieval = session.get('last_requirements_retrieval')
            if self.check_last_retrieval_timestamps(session):
                self.log.debug('Last retrieval timestamp still okay')
                if self.required_roles and self.valid_discord_guild_role(session):
                    #stored roles check out
                    return True
                elif self.required_guilds and self.valid_discord_guild(session):
                    #stored guilds check out
                    return True
                else:
                    return False
            self.log.debug('Last retrievals was not in the given time...')
            self.log.debug(plain_auth_obj)
            enc_auth_obj = session.get(self.auth_service + '_auth')
            if plain_auth_obj is None and enc_auth_obj:
                self.log.debug('No plain auth object given, decrypting session')
                try:
                    #clear_session_auth_values(session, args)
                    plain_auth_obj = self.from_sensitive(enc_auth_obj)
                except: #catch-all... bad practice, but if that's the case, we do not need any further treatment right now
                    self.clear_session_auth_values(session)
                    self.log.debug('Failed decrypting enc_auth_obj')
                    return False
                #self.log.debug('Got ' + json.dumps(plain_auth_obj))
            #okay, last retrievals were not within 5minutes -> update guilds and roles
            #auth_obj = from_sensitive(args.secret_encryption_key, enc_auth_obj
            access_token = plain_auth_obj.get('access_token')
            #self.log.debug('Access token: ' + access_token)
            if access_token and self.update_requirements(session, access_token):
                #retrieving guilds and roles succeeded, recheck the roles/guilds
                self.log.debug('Checking roles stored in session')
                return (self.valid_discord_guild_role(session) and self.valid_discord_guild(session))
            else:
                #retrieving guilds failed... TODO: consider throwing errors
                self.log.debug('Getting roles failed')
                return False
        else:
            #no requirement for roles or guilds
            return True

    #Wrapper for last_role_retrieval_valid and last_guild_retrieval_valid
    #Additionally checks last_auth
    #checks the timestamps of roles and guilds, we do not want to update them every couple seconds
    def check_last_retrieval_timestamps(self, session):
        last_requirements_retrieval = session.get('last_requirements_retrieval')
        #check last auth timestamp for the case where user may just have authed
        last_auth_check = session.get('last_auth_check')
        self.log.debug('Last auth check')
        self.log.debug(last_auth_check)
        self.log.debug('Last requirements retrieval')
        self.log.debug(last_requirements_retrieval)
        self.log.debug('self.retrieval_period')
        self.log.debug(self.retrieval_period)
        self.log.debug(self.required_roles)
        self.log.debug(self.required_guilds)
        if ((last_requirements_retrieval and
            (self.required_roles or self.required_guilds)
            and (last_requirements_retrieval + self.retrieval_period) < time.time())
            or (last_requirements_retrieval and last_auth_check
                and last_requirements_retrieval < last_auth_check)
            ):
            self.log.debug('Last retrieval timestamps not okay')
            return False
        else:
            #self.log.debug('Last retrieval timestamps okay')
            return True

    # Checks the IDs of required guilds against the ones stored
    def valid_discord_guild(self, session):
        if self.required_guilds:
            usersGuilds = session.get('last_guild_ids')
            self.log.debug("Guilds stored in session.")
            self.log.debug(usersGuilds)
            required_guilds = [x.strip() for x in self.required_guilds.split(',')]
            for g in usersGuilds:
                if g['id'] in required_guilds:
                    return True
            #self.log.debug("User not in required discord guild.")
            return False
        else:
            return True

    # Checks the IDs of required roles against the ones stored
    def valid_discord_guild_role(self, session):
        if self.required_roles:
            userRoles = session.get('last_guild_roles')
            requiredRoles = [x.strip() for x in self.required_roles.split(',')]
            for r in userRoles:
              if r in requiredRoles:
                return True
            #self.log.debug("User not in required discord guild role.")
            return False
        else:
            return True
