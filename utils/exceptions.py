#!/usr/bin/env python 3.6.8
# -*- coding: utf-8 -*-
# author sunkang


class CmdCallError(Exception):
    """Exception for wrong cmd"""

    def __init__(self, msg=None):
        self.msg = msg

    def __str__(self):
        return ("Error occurred executing command - %s", str(self.msg))

    def __repr__(self):
        return 'ReplyError('+str(self.msg)+')'


class NoSuchFileError(Exception):
    """Exception for no such file"""

    def __init__(self, msg=None):
        self.msg = msg

    def __str__(self):
        return ("File is not existed - %s", str(self.msg))

    def __repr__(self):
        return 'ReplyError('+str(self.msg)+')'

class NoNeededInfoError(Exception):
    """Exception for no needed info"""

    def __init__(self, msg=None):
        self.msg = msg

    def __str__(self):
        return ("File don't has needed info - %s", str(self.msg))

    def __repr__(self):
        return 'ReplyError('+str(self.msg)+')'

class ProcessFileError(Exception):
    """Exception for file processing"""

    def __init__(self, msg=None):
        self.msg = msg

    def __str__(self):
        return ("Error occurred processing file - %s", str(self.msg))

    def __repr__(self):
        return 'ReplyError('+str(self.msg)+')'