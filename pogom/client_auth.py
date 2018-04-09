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
from simplecrypt import encrypt, decrypt

log = logging.getLogger(__name__)

def to_sensitive(key, sens_obj):
    plain = json.dumps(sens_obj, ensure_ascii=False)
    log.debug("Encrypting the following string")
    log.debug(plain)
    cipher = encrypt(key, plain)
    return cipher

def from_sensitive(key, stored):
    plain = decrypt(key, stored)
    log.debug("Decrypted the following string")
    log.debug(plain)
    retrieveObject = json.loads(plain)
    return retrieveObject


def check_auth(req, args, url_root, session):
    if args.user_auth_service == "Discord":
        host = args.uas_host_override
        if not host:
            host = url_root
        #check if previous auth is present and valid
        auth_tuple = valid_session_client_auth(req, host, session, args)
        if (auth_tuple[0] and
            check_guilds_and_roles(req, host, session, args, auth_tuple[1])):
            log.debug('everything checks out, cya')
            return None
        else:
            return redirect_client_to_auth(host, args)
    return None

def redirect_client_to_auth(host, args):
    return redirect('https://discordapp.com/api/oauth2/authorize?client_id=' + args.uas_client_id + '&redirect_uri=' + urllib.quote(host + 'auth_callback') + '&response_type=code&scope=identify%20guilds')


def last_guild_retrieval_valid(session):
    log.debug('Checking last guild retrieval timestamp')
    last_guild_retrieval = session.get('last_guild_retrieval')
    if not last_guild_retrieval:
        #no previous retrieval?
        log.debug('No timestamp found')
        return False
    elif time.time() > (last_guild_retrieval + 86400):
        log.debug('Validity expired')
        #current time passed previous guild retrieval
        return False
    else:
        log.debug('Timestamp is okay')
        return True

def last_role_retrieval_valid(session):
    log.debug('Checking last role retrieval timestamp')
    last_role_retrieval = session.get('last_guild_roles_retrieval')
    if not last_role_retrieval:
        #no previous role retrieval?
        log.debug('no timestamp found')
        return False
    elif time.time() > (last_role_retrieval + 86400):
        log.debug('Validity expired')
        #current time passed previous guild role retrieval
        return False
    else:
        log.debug('Timestamp is okay')
        return True

def valid_session_client_auth(req, host, session, args):
    last_auth_check = session.get('last_auth_check')
    if not last_auth_check:
        log.info('No previous auth in session')
        #no previous auth, let's have the user auth
        return (False, {})
    elif time.time() > (last_auth_check + 86400): #check the auth at least every 24hours
        return refresh_auth(req, host, session, args)
    else:
        return (True, session.get(args.user_auth_service +'_auth'))

def clear_session_auth_values(session, args):
    session.pop(args.user_auth_service +'_auth')
    session.pop('last_auth_check')
    session.pop('last_guild_retrieval')
    session.pop('last_guild_ids')
    session.pop('last_guild_roles')
    session.pop('last_guild_roles_retrieval')

#returns bool
#checks cookie data, if okay -> store in session
def refresh_auth(req, host, session, args):
    #encryptedData = req.cookies.get(args.user_auth_service + '_auth')
    #if not encryptedData:
    #    #no cookie/auth ever processed, shouldn't even be the case here...
    #    return False

    #cookie-data present, check the session
    sessionData = session.get(args.user_auth_service + '_auth')
    if not sessionData:
        #no sessionData, check the cookie's data and update the session if it checks out
        plainData = from_sensitive(encryptedData)
        if check_valid_discord_auth_object(plainData):
            #the cookie's token is still valid
            #TODO: consider refresh
            #for the moment, just use some processing power to transform plainData, we could modify it
            session[args.user_auth_service + '_auth'] = to_sensitive(plainData)
            session['last_auth_check'] = time.time()
            return (True, plainData)
        else:
            #cookie does not have valid data....
            #resp.set_cookie(args.user_auth_service +'_auth', '', expires=0)
            clear_session_auth_values(session, args)
            return (False, {})
    else:
        #we got data in the session, let's check it for validity
        plainData = from_sensitive(sessionData)
        if check_valid_discord_auth_object():
            #the sessions's token is still valid
            #TODO: consider refresh
            #for the moment, just use some processing power to transform plainData, we could modify it
            session[args.user_auth_service + '_auth'] = to_sensitive(plainData)
            session['last_auth_check'] = time.time()
            return (True, plainData)
        else:
            #the session's token is invalid, bye
            #resp.set_cookie(args.user_auth_service +'_auth', '', expires=0)
            clear_session_auth_values(session, args)
            return (False, {})

def check_valid_discord_auth_object(auth_obj):
    log.debug('Checking auth object')
    if not auth_obj:
        log.debug('Auth object not valid')
        return False

    if auth_obj['expires_at'] < time.time():
        log.debug('OAuth expired')
        return False
    else:
        log.debug('OAuth valid until: ' + auth_obj['expires_at'])
        return True

def check_guilds_stored(session, args):
    if args.uas_discord_required_guilds:
        guilds_in_session = session.get('last_guild_ids')
        last_guild_retrieval = session.get('last_guild_retrieval')
        if (not guilds_in_session or not last_guild_retrieval
            or not last_guild_retrieval_valid(session)):
            return False
        else:
            return valid_discord_guild(session, args)
    else:
        return True

def check_roles_stored(session, args):
    if args.uas_discord_required_roles:
        roles_in_session = session.get('last_guild_roles')
        last_role_retrieval = session.get('last_guild_roles_retrieval')
        if (not roles_in_session or not last_role_retrieval
            or not last_role_retrieval_valid(session)):
            return False
        else:
            return valid_discord_guild_role(session, args)
    else:
        return True

#checks the timestamps of roles and guilds, we do not want to update them every couple seconds
def check_last_retrieval_timestamps(session, args):
    last_role_retrieval = session.get('last_guild_roles_retrieval')
    last_guild_retrieval = session.get('last_guild_retrieval')
    if ((args.uas_discord_required_roles and last_role_retrieval
            and last_role_retrieval > time.time() - 300)
        or (args.uas_discord_required_guilds and last_guild_retrieval
            and last_guild_retrieval > time.time() - 300)):
        return False
    return True



#wrapper for check_guilds and check_roles
def check_guilds_and_roles(req, host, session, args, enc_auth_obj):
    if args.uas_discord_required_guilds or args.uas_discord_required_roles:
        if not check_last_retrieval_timestamps(session, args):
            if args.uas_discord_required_roles and check_roles_stored(session, args):
                #stored roles check out
                return True
            elif args.uas_discord_required_guilds and check_guilds_stored(session, args):
                #stored guilds check out
                return True
            else:
                return False

        #okay, last retrievals were not within 5minutes -> update guilds and roles
        #TODO: consider checking the access token/refresh tokens
        auth_obj = from_sensitive(args.secret_encryption_key, enc_auth_obj)
        if get_guilds_and_roles(session, auth_obj['access_token'], args):
            #retrieving guilds and roles succeeded, recheck the roles/guilds
            return check_roles_stored(session, args) or check_guilds_stored(session, args)
        else:
            #retrieving guilds failed... TODO: consider throwing errors
            return False
    else:
        #no requirement for roles or guilds
        return True

def valid_discord_guild(session, args):
    usersGuilds = session.get('last_guild_ids')
    required_guilds = [x.strip() for x in args.uas_discord_required_guilds.split(',')]
    for g in usersGuilds:
        if g['id'] in required_guilds:
            return True
    log.debug("User not in required discord guild.")
    return False


def valid_discord_guild_role(session, args):
    userRoles = session.get('last_guild_roles')
    requiredRoles = [x.strip() for x in args.uas_discord_required_roles.split(',')]
    for r in userRoles:
      if r in requiredRoles:
        return True
    log.debug("User not in required discord guild role.")
    return False

def redirect_to_discord_guild_invite(args):
    return redirect(args.uas_discord_guild_invite)


def exchange_code(code, host, args, session):
    data = {
      'client_id': args.uas_client_id,
      'client_secret': args.uas_client_secret,
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': host + "auth_callback"
    }
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post(
        '%s/oauth2/token' % 'https://discordapp.com/api/v6', data, headers)
    try:
        r.raise_for_status()
    except HTTPError:
        log.debug('' + str(r.status_code) +
                  ' returned from OAuth attempt: ' +
                  r.text)
        return False
    jsonResponse = r.json()
    expires_in = jsonResponse.get('expires_in')
    expiration_date = time.time() + int(expires_in)
    jsonResponse['expires_at'] = expiration_date
    session['last_auth_check'] = time.time()
    return jsonResponse

#wrapper for getting guilds and roles
def get_guilds_and_roles(session, auth_token, args):
    updateSuccess = True
    if args.uas_discord_required_guilds:
        updateSuccess = get_user_guilds(session, auth_token)
    if args.uas_discord_required_roles:
        updateSuccess = updateSuccess and get_user_guild_roles(session, auth_token, args)
    return updateSuccess

def get_user_guilds(session, auth_token):
    headers = {
      'Authorization': 'Bearer ' + auth_token
    }
    r = requests.get('https://discordapp.com/api/v6/users/@me/guilds',
                     headers=headers)
    try:
        r.raise_for_status()
    except Exception:
        log.debug('' + str(r.status_code) +
                  ' returned from guild list attempt: ' +
                  r.text)
        return False
    session['last_guild_ids'] = r.json()
    session['last_guild_retrieval'] = time.time()
    log.debug('Guilds updated')
    return True

def get_user_guild_roles(session, auth_token, args):
    headers = {
      'Authorization': 'Bearer ' + auth_token
    }
    r = requests.get('https://discordapp.com/api/v6/users/@me',
                     headers=headers)
    try:
        r.raise_for_status()
    except Exception:
        log.debug('' + str(r.status_code) +
                  ' returned from Discord @me attempt: ' +
                  r.text)
        return False
    user_id = r.json()['id']
    headers = {
      'Authorization': 'Bot ' + args.uas_discord_bot_token
    }
    r = requests.get(
        'https://discordapp.com/api/v6/guilds/' +
        args.uas_discord_required_guilds.split(',')[0].strip() +
        '/members/' + user_id, headers=headers)
    try:
        r.raise_for_status()
    except Exception:
        log.debug('' + str(r.status_code) +
                  ' returned from Discord guild member attempt: ' +
                  r.text)
        return False
    session['last_guild_roles'] = r.json()['roles']
    session['last_guild_roles_retrieval'] = time.time()
    log.debug('Roles updated')
    return True
