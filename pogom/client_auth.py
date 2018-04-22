#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
import urllib
import datetime

from flask import redirect
from requests.exceptions import HTTPError

log = logging.getLogger(__name__)


def check_auth(args, url_root, session, user_auth_code_cache):
    if args.user_auth_service == "Discord":
        host = args.uas_host_override
        if not host:
            host = url_root
        if not valid_client_auth(host, session, user_auth_code_cache, args):
            return redirect_client_to_auth(host, args)
        if args.uas_discord_required_guilds:
            if not valid_discord_guild(session, user_auth_code_cache, args):
                log.debug('User is not in guild, redirecting...')
                return redirect_to_discord_guild_invite(args)
            if args.uas_discord_required_roles and \
                not valid_discord_guild_role(session,
                                             user_auth_code_cache, args):
                log.debug("User does not have required role, redirecting...")
                return redirect_to_discord_guild_invite(args)
    return None


def redirect_client_to_auth(host, args):
    return redirect(
        'https://discordapp.com/api/oauth2/authorize?client_id=' +
        args.uas_client_id + '&redirect_uri=' +
        urllib.quote(host + 'auth_callback') +
        '&response_type=code&scope=identify%20guilds'
    )


def valid_client_auth(host, session, user_auth_code_cache, args):
    userAuthCode = session.get('userAuthCode')
    if not userAuthCode:
        log.debug("No userAuthCode")
        return False
    oauth_response = user_auth_code_cache.get(userAuthCode, False)
    if not oauth_response:
        oauth_response = exchange_code(userAuthCode, host, args)
        if not oauth_response:
            log.debug("Unable to authorize code")
            return False
        user_auth_code_cache[userAuthCode] = oauth_response
        user_auth_code_cache[userAuthCode]['expires'] = \
            datetime.datetime.now() + \
            datetime.timedelta(0, int(oauth_response.get('expires_in')))
    if user_auth_code_cache[userAuthCode]['expires'] < datetime.datetime.now():
        log.debug("Oauth expired")
        del user_auth_code_cache[userAuthCode]
        return False
    if args.uas_discord_required_guilds:
        if not user_auth_code_cache[userAuthCode].get('guilds', False):
            user_auth_code_cache[userAuthCode]['guilds'] = get_user_guilds(
                user_auth_code_cache[userAuthCode]['access_token'])
            if not user_auth_code_cache[userAuthCode]['guilds']:
                log.debug("Unable to access user guilds.")
                del user_auth_code_cache[userAuthCode]
                return False
        if args.uas_discord_required_roles:
            if not user_auth_code_cache[userAuthCode].get('roles', False):
                user_auth_code_cache[userAuthCode]['roles'] = \
                    get_user_guild_roles(
                        user_auth_code_cache[userAuthCode]['access_token'],
                        args)
                if not user_auth_code_cache[userAuthCode]['roles']:
                    log.debug("Unable to access user roles.")
                    del user_auth_code_cache[userAuthCode]
                    return False
    return True


def valid_discord_guild(session, user_auth_code_cache, args):
    userAuthCode = session.get('userAuthCode')
    guilds = user_auth_code_cache.get(userAuthCode, {}).get('guilds')
    required_guilds = [x.strip() for x in
                       args.uas_discord_required_guilds.split(',')]
    for g in guilds:
        if g['id'] in required_guilds:
            return True
    log.debug("User not in required discord guild.")
    del user_auth_code_cache[userAuthCode]['guilds']
    return False


def valid_discord_guild_role(session, user_auth_code_cache, args):
    userAuthCode = session.get('userAuthCode')
    userRoles = user_auth_code_cache.get(userAuthCode, {}).get('roles')
    requiredRoles = [x.strip() for x in
                     args.uas_discord_required_roles.split(',')]
    for r in userRoles:
        if r in requiredRoles:
            return True
    log.debug("User not in required discord guild role.")
    del user_auth_code_cache[userAuthCode]['roles']
    return False


def redirect_to_discord_guild_invite(args):
    return redirect(args.uas_discord_guild_invite)


def exchange_code(code, host, args):
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
        log.debug(str(r.status_code) +
                  ' returned from OAuth attempt: ' + r.text)
        return False
    return r.json()


def get_user_guilds(auth_token):
    headers = {
        'Authorization': 'Bearer ' + auth_token
    }
    r = requests.get('https://discordapp.com/api/v6/users/@me/guilds',
                     headers=headers)
    try:
        r.raise_for_status()
    except Exception:
        log.debug(str(r.status_code) +
                  ' returned from guild list attempt: ' + r.text)
        return False
    return r.json()


def get_user_guild_roles(auth_token, args):
    headers = {
        'Authorization': 'Bearer ' + auth_token
    }
    r = requests.get('https://discordapp.com/api/v6/users/@me',
                     headers=headers)
    try:
        r.raise_for_status()
    except Exception:
        log.debug(str(r.status_code) +
                  ' returned from Discord @me attempt: ' + r.text)
        return False
    user_id = r.json()['id']
    headers = {
        'Authorization': 'Bot ' + args.uas_discord_bot_token
    }
    r = requests.get(
        'https://discordapp.com/api/v6/guilds/' +
        args.uas_discord_required_guilds.split(',')[0].strip() +
        '/members/' + user_id, headers=headers
    )
    try:
        r.raise_for_status()
    except Exception:
        log.debug(str(r.status_code) +
                  ' returned from Discord guild member attempt: ' + r.text)
        return False
    return r.json()['roles']
