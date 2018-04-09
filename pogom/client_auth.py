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
        if auth_tuple[0]:
            return check_guilds_and_roles(req, host, session, args, from_sensitive(args.secret_encryption_key, auth_tuple[1]))
        else:
            return redirect_client_to_auth(host, args)
    return None

def redirect_client_to_auth(host, args):
    return redirect('https://discordapp.com/api/oauth2/authorize?client_id=' + args.uas_client_id + '&redirect_uri=' + urllib.quote(host + 'auth_callback') + '&response_type=code&scope=identify%20guilds')


def last_guild_check_valid(session):
    last_guild_check = session.get('last_guild_check')
    if not valid_until:
        #no previous check?
        return False
    elif time.time() > (last_guild_check + 86400):
        #current time passed previous guild check
        return False
    else:
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
    session.pop('last_guild_check')
    session.pop('last_guild_ids')
    session.pop('last_guild_roles')

#returns bool
#checks cookie data, if okay -> store in session
def refresh_auth(req, host, session, args):
    encryptedData = req.cookies.get(args.user_auth_service + '_auth')
    if not encryptedData:
        #no cookie/auth ever processed, shouldn't even be the case here...
        return False

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
            resp.set_cookie(args.user_auth_service +'_auth', '', expires=0)
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
            resp.set_cookie(args.user_auth_service +'_auth', '', expires=0)
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

def check_guilds_and_roles(req, host, session, args, auth_obj):
    if args.uas_discord_required_guilds:
        #check for guilds in session
        guilds_in_session = session.get('last_guild_ids')
        last_guild_check = session.get('last_guild_check')
        last_check_valid = True
        if (not guilds_in_session or not last_guild_check
            or not last_guild_check_valid(session)):
            last_check_valid = False;
            #either no guilds in session or last_guild_check invalid
            log.debug(json.dumps(auth_obj, ensure_ascii=False))
            if not get_user_guilds(session, auth_obj['access_token']):
                #couldn't get the user's guilds
                return False
        #everything should be fine with the session now
        #check the guild IDs
        if not valid_discord_guild(session, args):
            return False
        elif args.uas_discord_required_roles:
            #check session for roles
            roles_in_session = session.get('last_guild_roles')
            if (not last_check_valid
                and not get_user_guild_roles(session, auth_obj['access_token'])):
                #no roles in session yet and retrieving failed
                return False
            #roles should now be valid
            if not valid_discord_guild_role(session, args):
                return False
            else:
                return True
        else:
            #everything checks out :)
            return True
    else:
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
    return True

def get_user_guild_roles(auth_token, args):
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
    return True
