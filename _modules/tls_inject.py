#!/usr/bin/env python
# -*- coding: utf-8 -*-
r'''
Inject functions into the upstream ``tls`` execution module.
'''

# Import python libs
from __future__ import absolute_import
import calendar
import logging
import os
import re
import time

# Import salt libs
import salt.utils.files
import salt.utils.path
import salt.utils.platform
from salt.exceptions import CommandExecutionError, SaltInvocationError

# Import 3rd-party libs
from salt.ext.six.moves import shlex_quote as _cmd_quote

log = logging.getLogger(__name__)

__virtualname__ = 'tls'


def __virtual__():
    return __virtualname__


def get_component(pem):
    r'''
    Returns the component type.
    '''
    ret = ''
    res = get_pem(pem)
    if len(res) > 1:
        raise CommandExecutionError('Too many PEM blocks')
    if len(res) == 0:
        return ret
    line = res[0].split('\n')[0]
    match = re.search('^-----BEGIN ([A-Z ]+)-----$', line)
    if match:
        label = match.group(1)
        if label in ('PRIVATE KEY', 'RSA PRIVATE KEY'):
            ret = 'key'
        elif label in ('CERTIFICATE', 'X509 CERTIFICATE'):
            ret = 'cert'
        elif label in ('DH PARAMETERS'):
            ret = 'dh'
    return ret


def get_expire_sec(pem):
    r'''
    Returns the expiration of a certificate in seconds from now.
    '''
    ret = None
    if not get_component(pem) == 'cert':
        return ret
    res = get_pem(pem, 'cert')
    if not res:
        return ret
    stdin = res[0]
    cmd = 'openssl'
    opts = 'asn1parse'
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)), stdin=stdin)
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    validity = []
    # see RFC 5280, section 4.1.2.5 "Validity"
    for line in res['stdout'].split('\n'):
        # for dates before 2050, YYMMDDHHMMSSZ
        match = re.search('UTCTIME[ ]*:([0-9]+)Z', line)
        if match:
            if int(match.group(1)[0:2]) >= 50:
                C = '19'
            else:
                C = '20'
            validity.append(C + match.group(1))
        # for dates after 2050, YYYYMMDDHHMMSSZ
        match = re.search('GENERALIZEDTIME[ ]*:([0-9]+)Z', line)
        if match:
            validity.append(match.group(1))
    not_after = sorted(validity)[-1]
    y = int(not_after[0:4])
    m = int(not_after[4:6])
    d = int(not_after[6:8])
    H = int(not_after[8:10])
    M = int(not_after[10:12])
    S = int(not_after[12:14])
    # all certificate times are in UTC
    exp = calendar.timegm((y, m, d, H, M, S))
    # be sure the current time is UTC also
    cur = int(time.mktime(time.gmtime()))
    ret = exp - cur
    return ret


def get_length(pem, component=None):
    r'''
    Returns the length of a PEM-encoded component.
    '''
    ret = None
    if not component:
        component = get_component(pem)
    if component == 'key':
        subcmd = 'rsa'
    elif component == 'cert':
        subcmd = 'x509'
    elif component == 'dh':
        subcmd = 'dhparam'
    else:
        return ret
    res = get_pem(pem, component)
    if not res:
        return ret
    stdin = res[0]
    cmd = 'openssl'
    opts = ' '.join((subcmd, '-text', '-noout'))
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)), stdin=stdin)
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    match = re.search(r'\(([0-9]+) bit\)', res['stdout'])
    if match:
        ret = int(match.group(1))
    return ret


def get_modulus(pem, component=None):
    r'''
    Returns the modulus of a PEM-encoded component.
    '''
    ret = None
    if not component:
        component = get_component(pem)
    if component == 'key':
        subcmd = 'rsa'
    elif component == 'cert':
        subcmd = 'x509'
    else:
        return ret
    res = get_pem(pem, component)
    if not res:
        return ret
    stdin = res[0]
    cmd = 'openssl'
    opts = ' '.join((subcmd, '-modulus', '-noout'))
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)), stdin=stdin)
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    match = re.search('^Modulus=([0-9A-F]+)$', res['stdout'])
    if match:
        ret = match.group(1)
    return ret


def get_pem(pem, component=None):
    r'''
    Returns a list of PEM-encoded components.
    '''
    ret = []
    if isinstance(pem, basestring):
        if os.path.isfile(pem):
            with salt.utils.files.fopen(pem, 'r') as f:
                lines = f.readlines()
        else:
            lines = pem.split('\n')
    else:
        lines = pem
    labels = []
    if component in (None, 'key'):
        labels.append('PRIVATE KEY')
        labels.append('RSA PRIVATE KEY')
    if component in (None, 'cert'):
        labels.append('CERTIFICATE')
        labels.append('X509 CERTIFICATE')
    if component in (None, 'dh'):
        labels.append('DH PARAMETERS')
    for label in labels:
        _is_pem = False
        for line in lines:
            line = line.rstrip('\n')
            if line == '-----BEGIN ' + label + '-----':
                _is_pem = True
                msg = [line]
                continue
            if _is_pem:
                if re.search(r'^[a-zA-Z0-9+/=]+$', line):
                    msg.append(line)
                    continue
                if line == '-----END ' + label + '-----':
                    msg.append(line)
                    ret.append('\n'.join(msg))
                _is_pem = False
                del msg
    return ret


def generate_cert(key, config=None, subj='/CN=localhost', expire=30):
    r'''
    Generate a self-signed certificate.

    key
        The PEM-encoded RSA private key.

    config
        The location of an OpenSSL configuration file on the minion, useful
        for specifying X.509 extensions in generated certificates.

    subj
        The subject name of the certificate, using ``/`` to separate relative
        distinguished names. Default is ``/CN=localhost``.

    expire
        Number of days until the certificate expires. Default is ``30``.
    '''
    ret = ''
    if subj is None:
        subj = '/CN=localhost'
    cmd = 'openssl'
    opts = ['req -new -x509 -sha256 -batch']
    if salt.utils.platform.is_windows():
        opts.append('-key -')
    else:
        opts.append('-key /dev/stdin')
    if config:
        if not os.path.exists(config):
            raise CommandExecutionError(
                '\'{0}\' file not found on minion'.format(config)
            )
        opts.append(' '.join(('-config', _cmd_quote(config))))
    opts.append(' '.join(('-subj', _cmd_quote(subj))))
    try:
        expire = int(expire)
    except TypeError:
        raise SaltInvocationError(
            '\'{0}\' is not an integer'.format(expire)
        )
    opts.append(' '.join(('-days', str(expire))))
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    opts = ' '.join(opts)
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)), stdin=key)
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    ret = res['stdout']
    return ret


def generate_dh(bits=2048):
    r'''
    Generate a Diffie-Hellman parameter set.

    .. note::
        This can take a long time.
    '''
    ret = ''
    try:
        bits = int(bits)
    except TypeError:
        raise SaltInvocationError(
            '\'{0}\' is not an integer'.format(bits)
        )
    if bits < 2048:
        log.warning('insecure DH parameter set length')
    if bits not in (2048, 4096, 8192):
        log.warning('non-standard DH parameter set length')
    cmd = 'openssl'
    opts = ' '.join(('dhparam', str(bits)))
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)))
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    ret = res['stdout']
    return ret


def generate_key(bits=2048):
    r'''
    Generate an RSA private key.
    '''
    ret = ''
    try:
        bits = int(bits)
    except TypeError:
        raise SaltInvocationError(
            '\'{0}\' is not an integer'.format(bits)
        )
    if bits < 2048:
        log.warning('insecure RSA private key length')
    if bits not in (2048, 4096, 8192):
        log.warning('non-standard RSA private key length')
    cmd = 'openssl'
    opts = ' '.join(('genrsa', str(bits)))
    if not salt.utils.path.which(cmd):
        raise CommandExecutionError(
            '\'{0}\' command not found on minion'.format(cmd)
        )
    res = __salt__['cmd.run_all'](' '.join((cmd, opts)))
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    ret = res['stdout']
    return ret
