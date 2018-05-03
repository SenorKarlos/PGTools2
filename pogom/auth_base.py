#!/usr/bin/python
# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod

class AuthBase:
    __metaclass__ = ABCMeta

    @abstractmethod
    def check_auth(req, session):
        pass

    @abstractmethod
    def to_sensitive(sens_obj):
        pass

    @abstractmethod
    def from_sensitive(stored):
        pass

    @abstractmethod
    def update_requirements(session, additionalInformation):
        pass
